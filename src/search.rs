use std::path::Path;

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use chrono_tz::Tz;
use regex::{RegexSet, RegexSetBuilder};
use serde_json::Value as Json;
use tau_engine::{
    core::parser::{BoolSym, Expression},
    Document as Doc,
};

use crate::ext;
use crate::file::{Document, Documents, Reader};

pub struct Hits<'a> {
    reader: Reader,
    searcher: &'a SearcherInner,
}

impl<'a> Hits<'a> {
    pub fn iter(&mut self) -> Iter<'_> {
        Iter {
            documents: self.reader.documents(),
            searcher: self.searcher,
        }
    }
}

pub struct Iter<'a> {
    documents: Documents<'a>,
    searcher: &'a SearcherInner,
}

impl<'a> Iterator for Iter<'a> {
    type Item = crate::Result<Json>;

    fn next(&mut self) -> Option<Self::Item> {
        for document in self.documents.by_ref() {
            let document = match document {
                Ok(document) => document,
                Err(e) => {
                    if self.searcher.skip_errors {
                        continue;
                    }
                    return Some(Err(e));
                }
            };
            if self.searcher.timestamp.is_some()
                && (self.searcher.from.is_some() || self.searcher.to.is_some())
            {
                let field = self
                    .searcher
                    .timestamp
                    .as_ref()
                    .expect("could not get timestamp");
                // TODO: Default to RFC 3339
                let result = match &document {
                    Document::Evtx(evtx) => {
                        match crate::evtx::WrapperLegacy(&evtx.data).find(field) {
                            Some(value) => match value.as_str() {
                                Some(timestamp) => NaiveDateTime::parse_from_str(
                                    timestamp,
                                    "%Y-%m-%dT%H:%M:%S%.6fZ",
                                ),
                                None => continue,
                            },
                            None => continue,
                        }
                    }
                    Document::Hve(json)
                    | Document::Json(json)
                    | Document::Xml(json)
                    | Document::Mft(json) => match json.find(field) {
                        Some(value) => match value.as_str() {
                            Some(timestamp) => {
                                NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%dT%H:%M:%S%.6fZ")
                            }
                            None => continue,
                        },
                        None => continue,
                    },
                };
                let timestamp = match result {
                    Ok(t) => t,
                    Err(e) => {
                        if self.searcher.skip_errors {
                            cs_eyellowln!("failed to parse timestamp - {}", e);
                            continue;
                        } else {
                            return Some(Err(anyhow::anyhow!("failed to parse timestamp - {}", e)));
                        }
                    }
                };
                // TODO: Not sure if this is correct...
                let localised = if let Some(timezone) = self.searcher.timezone {
                    let local = match timezone.from_local_datetime(&timestamp).single() {
                        Some(l) => l,
                        None => {
                            if self.searcher.skip_errors {
                                cs_eyellowln!("failed to localise timestamp");
                                continue;
                            } else {
                                return Some(Err(anyhow::anyhow!("failed to localise timestamp")));
                            }
                        }
                    };
                    local.with_timezone(&Utc)
                } else if self.searcher.local {
                    match Utc.from_local_datetime(&timestamp).single() {
                        Some(l) => l,
                        None => {
                            if self.searcher.skip_errors {
                                cs_eyellowln!("failed to localise timestamp");
                                continue;
                            } else {
                                return Some(Err(anyhow::anyhow!("failed to localise timestamp")));
                            }
                        }
                    }
                } else {
                    DateTime::<Utc>::from_utc(timestamp, Utc)
                };
                // Check if event is older than start date marker
                if let Some(sd) = self.searcher.from {
                    if localised <= sd {
                        continue;
                    }
                }
                // Check if event is newer than end date marker
                if let Some(ed) = self.searcher.to {
                    if localised >= ed {
                        continue;
                    }
                }
            }
            // TODO: Remove duplication...
            match document {
                Document::Evtx(evtx) => {
                    let wrapper = crate::evtx::WrapperLegacy(&evtx.data);
                    if let Some(expression) = &self.searcher.tau {
                        if !tau_engine::core::solve(expression, &wrapper) {
                            continue;
                        }
                        if self.searcher.regex.is_empty() {
                            return Some(Ok(evtx.data));
                        }
                    }
                    if evtx.matches(&self.searcher.regex) {
                        return Some(Ok(evtx.data));
                    }
                }
                Document::Hve(json)
                | Document::Json(json)
                | Document::Xml(json)
                | Document::Mft(json) => {
                    if let Some(expression) = &self.searcher.tau {
                        if !tau_engine::core::solve(expression, &json) {
                            continue;
                        }
                        if self.searcher.regex.is_empty() {
                            return Some(Ok(json));
                        }
                    }
                    if json.matches(&self.searcher.regex) {
                        return Some(Ok(json));
                    }
                }
            };
        }
        None
    }
}

pub trait Searchable {
    fn matches(&self, regex: &RegexSet) -> bool;
}

#[derive(Default)]
pub struct SearcherBuilder {
    patterns: Option<Vec<String>>,

    from: Option<NaiveDateTime>,
    ignore_case: Option<bool>,
    load_unknown: Option<bool>,
    local: Option<bool>,
    skip_errors: Option<bool>,
    tau: Option<Vec<String>>,
    timestamp: Option<String>,
    timezone: Option<Tz>,
    to: Option<NaiveDateTime>,
}

impl SearcherBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn build(self) -> crate::Result<Searcher> {
        let ignore_case = self.ignore_case.unwrap_or_default();
        let load_unknown = self.load_unknown.unwrap_or_default();
        let local = self.local.unwrap_or_default();
        let patterns = self.patterns.unwrap_or_default();
        let skip_errors = self.skip_errors.unwrap_or_default();
        let tau = match self.tau {
            Some(kvs) => {
                let mut expressions = Vec::with_capacity(kvs.len());
                for kv in &kvs {
                    expressions.push(ext::tau::parse_kv(kv)?);
                }
                if expressions.is_empty() {
                    None
                } else {
                    Some(Expression::BooleanGroup(BoolSym::And, expressions))
                }
            }
            None => None,
        };

        let regex = RegexSetBuilder::new(patterns)
            .case_insensitive(ignore_case)
            .build()?;

        Ok(Searcher {
            inner: SearcherInner {
                regex,

                from: self.from.map(|d| DateTime::from_utc(d, Utc)),
                load_unknown,
                local,
                skip_errors,
                tau,
                timestamp: self.timestamp,
                timezone: self.timezone,
                to: self.to.map(|d| DateTime::from_utc(d, Utc)),
            },
        })
    }

    pub fn from(mut self, datetime: NaiveDateTime) -> Self {
        self.from = Some(datetime);
        self
    }

    pub fn ignore_case(mut self, ignore: bool) -> Self {
        self.ignore_case = Some(ignore);
        self
    }

    pub fn load_unknown(mut self, allow: bool) -> Self {
        self.load_unknown = Some(allow);
        self
    }

    pub fn local(mut self, local: bool) -> Self {
        self.local = Some(local);
        self
    }

    pub fn patterns(mut self, patterns: Vec<String>) -> Self {
        self.patterns = Some(patterns);
        self
    }

    pub fn skip_errors(mut self, skip: bool) -> Self {
        self.skip_errors = Some(skip);
        self
    }

    pub fn tau(mut self, kvs: Vec<String>) -> Self {
        self.tau = Some(kvs);
        self
    }

    pub fn timestamp(mut self, field: String) -> Self {
        self.timestamp = Some(field);
        self
    }

    pub fn timezone(mut self, tz: Tz) -> Self {
        self.timezone = Some(tz);
        self
    }

    pub fn to(mut self, datetime: NaiveDateTime) -> Self {
        self.to = Some(datetime);
        self
    }
}

pub struct SearcherInner {
    regex: RegexSet,

    load_unknown: bool,
    local: bool,
    from: Option<DateTime<Utc>>,
    skip_errors: bool,
    tau: Option<Expression>,
    timestamp: Option<String>,
    timezone: Option<Tz>,
    to: Option<DateTime<Utc>>,
}

pub struct Searcher {
    inner: SearcherInner,
}

impl Searcher {
    pub fn builder() -> SearcherBuilder {
        SearcherBuilder::new()
    }

    pub fn search(&self, file: &Path) -> crate::Result<Hits<'_>> {
        let reader = Reader::load(file, self.inner.load_unknown, self.inner.skip_errors)?;
        Ok(Hits {
            reader,
            searcher: &self.inner,
        })
    }
}
