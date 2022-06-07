use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use anyhow::Error;
use regex::RegexSet;
pub use serde_json::Value as Json;

use crate::search::Searchable;

pub struct Parser {
    pub inner: Option<Json>,
}

impl Parser {
    pub fn load(path: &Path) -> crate::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let json = serde_json::from_reader(reader)?;
        Ok(Self { inner: Some(json) })
    }

    pub fn parse(&mut self) -> impl Iterator<Item = Result<Json, Error>> + '_ {
        if let Some(json) = self.inner.take() {
            return match json {
                Json::Array(array) => array.into_iter().map(Ok).collect::<Vec<_>>().into_iter(),
                _ => vec![json]
                    .into_iter()
                    .map(Ok)
                    .collect::<Vec<_>>()
                    .into_iter(),
            };
        }
        vec![].into_iter()
    }
}

impl Searchable for Json {
    fn matches(&self, regex: &RegexSet) -> bool {
        regex.is_match(&self.to_string())
    }
}
