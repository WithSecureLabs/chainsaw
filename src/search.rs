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

impl Hits<'_> {
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

impl Iterator for Iter<'_> {
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
                    | Document::Mft(json)
                    | Document::Esedb(json) => match json.find(field) {
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
                let localised = Utc.from_utc_datetime(&timestamp);
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
                    if evtx.matches(&self.searcher.regex, &self.searcher.match_any) {
                        return Some(Ok(evtx.data));
                    }
                }
                Document::Hve(json)
                | Document::Json(json)
                | Document::Xml(json)
                | Document::Mft(json)
                | Document::Esedb(json) => {
                    if let Some(expression) = &self.searcher.tau {
                        if !tau_engine::core::solve(expression, &json) {
                            continue;
                        }
                        if self.searcher.regex.is_empty() {
                            return Some(Ok(json));
                        }
                    }
                    if json.matches(&self.searcher.regex, &self.searcher.match_any) {
                        return Some(Ok(json));
                    }
                }
            };
        }
        None
    }
}

pub trait Searchable {
    fn matches(&self, regex: &RegexSet, match_any: &bool) -> bool;
}

#[derive(Default)]
pub struct SearcherBuilder {
    patterns: Option<Vec<String>>,

    from: Option<NaiveDateTime>,
    ignore_case: Option<bool>,
    load_unknown: Option<bool>,
    local: Option<bool>,
    match_any: Option<bool>,
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
        let match_any = self.match_any.unwrap_or_default();
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
                } else if match_any {
                    Some(Expression::BooleanGroup(BoolSym::Or, expressions))
                } else {
                    Some(Expression::BooleanGroup(BoolSym::And, expressions))
                }
            }
            None => None,
        };

        let regex = RegexSetBuilder::new(patterns)
            .case_insensitive(ignore_case)
            .build()?;

        let mut from = None;
        let mut to = None;
        if let Some(timestamp) = self.from {
            if let Some(timezone) = self.timezone {
                let local = match timezone.from_local_datetime(&timestamp).single() {
                    Some(l) => l,
                    None => {
                        anyhow::bail!("failed to localise timestamp");
                    }
                };
                from = Some(local.with_timezone(&Utc));
            } else if local {
                from = Some(match Utc.from_local_datetime(&timestamp).single() {
                    Some(l) => l,
                    None => {
                        anyhow::bail!("failed to localise timestamp");
                    }
                });
            } else {
                from = Some(Utc.from_utc_datetime(&timestamp));
            }
        }
        if let Some(timestamp) = self.to {
            if let Some(timezone) = self.timezone {
                let local = match timezone.from_local_datetime(&timestamp).single() {
                    Some(l) => l,
                    None => {
                        anyhow::bail!("failed to localise timestamp");
                    }
                };
                to = Some(local.with_timezone(&Utc));
            } else if local {
                to = Some(match Utc.from_local_datetime(&timestamp).single() {
                    Some(l) => l,
                    None => {
                        anyhow::bail!("failed to localise timestamp");
                    }
                });
            } else {
                to = Some(Utc.from_utc_datetime(&timestamp));
            }
        }

        Ok(Searcher {
            inner: SearcherInner {
                regex,

                from,
                load_unknown,
                match_any,
                skip_errors,
                tau,
                timestamp: self.timestamp,
                to,
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

    pub fn match_any(mut self, match_any: bool) -> Self {
        self.match_any = Some(match_any);
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
    match_any: bool,
    from: Option<DateTime<Utc>>,
    skip_errors: bool,
    tau: Option<Expression>,
    timestamp: Option<String>,
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
        let reader = Reader::load(
            file,
            self.inner.load_unknown,
            self.inner.skip_errors,
            true,
            None,
        )?;
        Ok(Hits {
            reader,
            searcher: &self.inner,
        })
    }
}
