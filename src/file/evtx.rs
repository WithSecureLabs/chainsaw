use std::fs::File;
use std::path::Path;

use evtx::{err::EvtxError, EvtxParser, ParserSettings, SerializedEvtxRecord};
use regex::RegexSet;
use serde_json::Value as Json;
use tau_engine::{Document, Value as Tau};

use crate::search::Searchable;
use crate::value::Value;

pub type Evtx = SerializedEvtxRecord<Json>;

pub struct Parser {
    pub inner: EvtxParser<File>,
}

impl Parser {
    pub fn load(file: &Path) -> crate::Result<Self> {
        let settings = ParserSettings::default()
            .separate_json_attributes(true)
            .num_threads(rayon::current_num_threads());
        let parser = EvtxParser::from_path(file)?.with_configuration(settings);
        Ok(Self { inner: parser })
    }

    pub fn parse(
        &mut self,
    ) -> impl Iterator<Item = Result<SerializedEvtxRecord<serde_json::Value>, EvtxError>> + '_ {
        self.inner.records_json_value()
    }
}

pub struct Wrapper<'a>(pub &'a Value);
impl Document for Wrapper<'_> {
    fn find(&self, key: &str) -> Option<Tau<'_>> {
        // As event logs can store values in a key or complex objects we do some aliasing here for
        // convenience...
        match key {
            "Event.System.Provider" => self.0.find("Event.System.Provider_attributes.Name"),
            "Event.System.TimeCreated" => self
                .0
                .find("Event.System.TimeCreated_attributes.SystemTime"),
            _ => self.0.find(key),
        }
    }
}
// FIXME: Remove the need for this, it requires a big rethink on the data structures, as `search` is
// the blocker here. It's actually quite easy to do, but just want to think it through first...
// This structure means that we don't get the lookup speed improvements from using `Value`.
pub struct WrapperLegacy<'a>(pub &'a Json);
impl Document for WrapperLegacy<'_> {
    fn find(&self, key: &str) -> Option<Tau<'_>> {
        // As event logs can store values in a key or complex objects we do some aliasing here for
        // convenience...
        match key {
            "Event.System.Provider" => self.0.find("Event.System.Provider_attributes.Name"),
            "Event.System.TimeCreated" => self
                .0
                .find("Event.System.TimeCreated_attributes.SystemTime"),
            _ => self.0.find(key),
        }
    }
}

impl Searchable for SerializedEvtxRecord<Json> {
    fn matches(&self, regex: &RegexSet, match_any: &bool) -> bool {
        if *match_any {
            regex.is_match(&self.data.to_string().replace(r"\\", r"\"))
        } else {
            regex
                .matches(&self.data.to_string().replace(r"\\", r"\"))
                .into_iter()
                .collect::<Vec<_>>()
                .len()
                == regex.len()
        }
    }
}
