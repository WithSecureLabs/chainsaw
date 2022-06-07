use std::fs::File;
use std::io::BufReader;
use std::path::Path;

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
                Json::Array(array) => array
                    .into_iter()
                    .map(|x| Ok(x))
                    .collect::<Vec<_>>()
                    .into_iter(),
                _ => vec![json]
                    .into_iter()
                    .map(|x| Ok(x))
                    .collect::<Vec<_>>()
                    .into_iter(),
            };
        }
        vec![].into_iter()
    }
}
