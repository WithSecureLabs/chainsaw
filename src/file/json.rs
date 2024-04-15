use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::vec::IntoIter;

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

    use std::io::prelude::*;
    use std::io::Lines;

    pub struct Parser {
        pub inner: Option<BufReader<File>>,
    }

    impl Parser {
        pub fn load(path: &Path) -> crate::Result<Self> {
            let file = File::open(path)?;
            let mut reader = BufReader::new(file);
            // A crude check where we read the first line to see if its JSON, we should probably
            // read more than this?
            let mut line = String::new();
            reader.read_line(&mut line)?;
            let _ = serde_json::from_str::<Json>(&line)?;
            reader.rewind()?;
            Ok(Self {
                inner: Some(reader),
            })
        }

        pub fn parse(&mut self) -> impl Iterator<Item = Result<Json, Error>> + '_ {
            if let Some(file) = self.inner.take() {
                return ParserIter(Some(file.lines()));
            }
            ParserIter(None)
        }
    }

    struct ParserIter(Option<Lines<BufReader<File>>>);

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
