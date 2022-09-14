use std::f32::consts::E;
use std::path::Path;
use std::{fs::File, io::BufReader};

use mft::csv::FlatMftEntryWithName;
use mft::{err::Error, MftEntry, MftParser};
use regex::RegexSet;
use serde_json::Value as Json;
use tau_engine::{Document, Value as Tau};

use crate::search::Searchable;

pub type Mft = Json;

pub struct Parser {
    pub inner: MftParser<BufReader<File>>,
}

impl Parser {
    pub fn load(file: &Path) -> crate::Result<Self> {
        let parser = MftParser::from_path(file)?;
        Ok(Self { inner: parser })
    }

    pub fn parse(&mut self) -> impl Iterator<Item = crate::Result<Json>> + '_ {
        // Really don't love this but I'm limited by parsing lib
        let entries: Vec<Result<MftEntry, mft::err::Error>> = self.inner.iter_entries().collect();
        let mut flat: Vec<crate::Result<FlatMftEntryWithName>> = vec![];
        for entry in entries {
            flat.push(match entry {
                Ok(e) => Ok(mft::csv::FlatMftEntryWithName::from_entry(
                    &e,
                    &mut self.inner,
                )),
                Err(err) => Err(anyhow!(err)),
            });
        }
        let mut json = vec![];
        for entry in flat {
            json.push(match entry {
                Ok(e) => match serde_json::to_value(e) {
                    Ok(j) => Ok(j),
                    Err(err) => Err(anyhow!(err)),
                },
                Err(err) => Err(anyhow!(err)),
            });
        }
        json.into_iter()
    }
}

pub struct Wrapper<'a>(pub &'a Json);
impl<'a> Document for Wrapper<'a> {
    fn find(&self, key: &str) -> Option<Tau<'_>> {
        // As event logs can store values in a key or complex objects we do some aliasing here for
        // convenience...
        match key {
            // "Event.System.TimeCreated" => self
            //     .0
            //     .find("Event.System.TimeCreated_attributes.SystemTime"),
            _ => self.0.find(key),
        }
    }
}

// impl Searchable for MftEntry {
//     fn matches(&self, regex: &RegexSet) -> bool {
//         match serde_json::to_string(self) {
//             Ok(s) => regex.is_match(&s),
//             Err(_) => false,
//         }
//     }
// }
