use std::fs::File;
use std::path::Path;

use evtx::{err::EvtxError, EvtxParser, ParserSettings, SerializedEvtxRecord};
use regex::RegexSet;
use serde_json::Value as Json;
use tau_engine::{Document, Value as Tau};

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

impl Searchable for SerializedEvtxRecord<Json> {
    fn matches(&self, regex: &RegexSet) -> bool {
        regex.is_match(&self.data.to_string())
    }
}
