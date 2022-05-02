use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::path::Path;

use evtx::{err::EvtxError, EvtxParser, ParserSettings, SerializedEvtxRecord};
use regex::RegexSet;
use serde_json::Value as Json;
use tau_engine::{Document, Value as Tau};

use crate::hunt::{Group, Huntable};
use crate::rule::Rule;
use crate::search::Searchable;

pub type Evtx = SerializedEvtxRecord<Json>;

pub struct Parser {
    pub inner: EvtxParser<File>,
}

impl Parser {
    pub fn load(file: &Path) -> crate::Result<Self> {
        let settings = ParserSettings::default()
            .separate_json_attributes(true)
            .num_threads(0);
        let parser = EvtxParser::from_path(file)?.with_configuration(settings);
        Ok(Self { inner: parser })
    }

    pub fn parse(
        &mut self,
    ) -> impl Iterator<Item = Result<SerializedEvtxRecord<serde_json::Value>, EvtxError>> + '_ {
        self.inner.records_json_value()
    }
}

pub struct Mapper<'a>(&'a HashMap<String, String>, &'a Wrapper<'a>);
impl<'a> Document for Mapper<'a> {
    fn find(&self, key: &str) -> Option<Tau<'_>> {
        self.0.get(key).and_then(|v| self.1.find(v))
    }
}

pub struct Wrapper<'a>(pub &'a Json);
impl<'a> Document for Wrapper<'a> {
    fn find(&self, key: &str) -> Option<Tau<'_>> {
        // As event logs can store values in a key or complex objects we do some aliasing here for
        // convenience...
        match key {
            "Event.System.EventID" => {
                // FIXME: If `#text` returns text then we need to map this to a u64 otherwise it
                // will be ignored...
                self.0
                    .find("Event.System.EventID.#text")
                    .or(self.0.find(key))
            }
            "Event.System.Provider" => self.0.find("Event.System.Provider_attributes.Name"),
            "Event.System.TimeCreated" => self
                .0
                .find("Event.System.TimeCreated_attributes.SystemTime"),
            _ => self.0.find(key),
        }
    }
}

impl Huntable for &SerializedEvtxRecord<Json> {
    fn hits(
        &self,
        rules: &[Rule],
        exclusions: &HashSet<String>,
        group: &Group,
    ) -> Option<Vec<String>> {
        let wrapper = Wrapper(&self.data);
        if tau_engine::core::solve(&group.filter, &wrapper) {
            let mut tags = vec![];
            for rule in rules {
                if exclusions.contains(&rule.tag) {
                    continue;
                }
                if rule.tau.matches(&Mapper(&group.fields, &wrapper)) {
                    tags.push(rule.tag.clone());
                }
            }
            return Some(tags);
        }
        None
    }
}

impl Searchable for SerializedEvtxRecord<Json> {
    fn matches(&self, regex: &RegexSet) -> bool {
        regex.is_match(&self.data.to_string())
    }
}
