use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::vec::IntoIter;

use anyhow::Error;
use serde_json::Value as Json;

// NOTE: Because we just deserialize into JSON, this looks pretty much the same as the JSON
// implementation. Maybe in time we will parse it differently...

pub type Xml = Json;

pub struct Parser {
    pub inner: Option<Json>,
}

impl Parser {
    pub fn load(path: &Path) -> crate::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let xml = quick_xml::de::from_reader(reader)?;
        Ok(Self { inner: Some(xml) })
    }

    pub fn parse(&mut self) -> impl Iterator<Item = Result<Json, Error>> + '_ {
        if let Some(json) = self.inner.take() {
            return match json {
                Json::Array(array) => ParserIter(Some(array.into_iter())),
                _ => ParserIter(Some(vec![json].into_iter())),
            };
        }
        ParserIter(None)
    }
}

struct ParserIter(Option<IntoIter<Json>>);

impl Iterator for ParserIter {
    type Item = Result<Json, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.0 {
            Some(i) => i.next().map(Ok),
            None => None,
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match &self.0 {
            Some(i) => i.size_hint(),
            None => (0, Some(0)),
        }
    }
}
