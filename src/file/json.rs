use flate2::read::GzDecoder;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::vec::IntoIter;

use anyhow::Error;
use regex::RegexSet;
pub use serde_json::Value as Json;

use crate::search::Searchable;

// We perform a crude check by looking for the "eventType" key in the first entry
// and matching it against a list of valid AWS CloudTrail event types
// If a match is found we flatten the records into a single array
fn is_cloudtrail_log(object: &serde_json::Map<String, Json>) -> Option<&Vec<Json>> {
    const VALID_EVENT_TYPES: &[&str] = &[
        "AwsApiCall",
        "AwsServiceEvent",
        "AwsConsoleAction",
        "AwsConsoleSignIn",
        "AwsVpceEvents",
    ];

    object
        .get("Records")
        .and_then(|v| v.as_array())
        .and_then(|records| {
            records
                .first()
                .and_then(|first| first.as_object())
                .and_then(|first_obj| first_obj.get("eventType"))
                .and_then(|event_type| event_type.as_str())
                .filter(|&event_type| VALID_EVENT_TYPES.contains(&event_type))
                .map(|_| records)
        })
}

pub struct Parser {
    pub inner: Option<Json>,
}

impl Parser {
    pub fn load(path: &Path, decoder: Option<GzDecoder<BufReader<File>>>) -> crate::Result<Self> {
        let json;
        if let Some(decoder) = decoder {
            json = serde_json::from_reader(decoder)?;
        } else {
            let file = File::open(path)?;
            let reader = BufReader::new(file);
            json = serde_json::from_reader(reader)?;
        }
        Ok(Self { inner: Some(json) })
    }

    pub fn parse(&mut self) -> impl Iterator<Item = Result<Json, Error>> + '_ {
        let json = match self.inner.take() {
            Some(json) => json,
            None => return ParserIter(None),
        };

        match json {
            Json::Array(array) => ParserIter(Some(array.into_iter())),
            Json::Object(ref object) => {
                // Handle AWS CloudTrail logs which have the format {Records: [entry,entry]}
                match is_cloudtrail_log(object) {
                    Some(records) => {
                        return ParserIter(Some(records.clone().into_iter()));
                    }
                    None => ParserIter(Some(vec![json].into_iter())),
                }
            }
            _ => ParserIter(Some(vec![json].into_iter())),
        }
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

impl Searchable for Json {
    fn matches(&self, regex: &RegexSet, match_any: &bool) -> bool {
        if *match_any {
            regex.is_match(&self.to_string().replace(r"\\", r"\"))
        } else {
            regex
                .matches(&self.to_string().replace(r"\\", r"\"))
                .into_iter()
                .collect::<Vec<_>>()
                .len()
                == regex.len()
        }
    }
}

pub mod lines {
    use super::*;

    use std::io::Lines;
    use std::io::prelude::*;

    pub struct Parser {
        pub inner: Option<BufReader<Box<dyn Read + Send + Sync>>>,
    }

    impl Parser {
        pub fn load(
            path: &Path,
            decoder: Option<GzDecoder<BufReader<File>>>,
        ) -> crate::Result<Self> {
            let reader: Box<dyn Read + Send + Sync> = match decoder {
                Some(decoder) => Box::new(decoder),
                None => Box::new(File::open(path)?),
            };
            Ok(Self {
                inner: Some(BufReader::new(reader)),
            })
        }

        pub fn parse(&mut self) -> impl Iterator<Item = Result<Json, Error>> + '_ {
            if let Some(file) = self.inner.take() {
                return ParserIter(Some(file.lines()));
            }
            ParserIter(None)
        }
    }

    struct ParserIter(Option<Lines<BufReader<Box<dyn Read + Send + Sync>>>>);

    impl Iterator for ParserIter {
        type Item = Result<Json, Error>;

        fn next(&mut self) -> Option<Self::Item> {
            match &mut self.0 {
                Some(i) => i.next().map(|l| match l {
                    Ok(l) => serde_json::from_str(l.as_str()).map_err(Error::from),
                    Err(e) => Err(Error::from(e)),
                }),
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
}
