use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use chrono_tz::Tz;
use serde::{de, Deserialize, Serialize};
use serde_json::Value as Json;
use serde_yaml::Value as Yaml;
use tau_engine::{
    core::parser::{parse_identifier, Expression},
    Document as Docu,
};

use crate::file::{Document as Doc, Reader};
use crate::rule::{Kind as RuleKind, Rule};

#[derive(Deserialize)]
pub struct Group {
    #[serde(default)]
    pub default: Option<Vec<String>>,
    pub fields: HashMap<String, String>,
    #[serde(deserialize_with = "deserialize_expression")]
    pub filter: Expression,
    pub name: String,
    pub timestamp: String,
}

fn deserialize_expression<'de, D>(deserializer: D) -> Result<Expression, D::Error>
where
    D: de::Deserializer<'de>,
{
    let yaml: Yaml = de::Deserialize::deserialize(deserializer)?;
    parse_identifier(&yaml).map_err(de::Error::custom)
}

#[derive(Deserialize)]
pub struct Mapping {
    #[serde(default)]
    pub exclusions: HashSet<String>,
    pub groups: Vec<Group>,
    pub kind: String,
    pub name: String,
    pub rules: RuleKind,
}

pub struct Hit {
    pub group: String,
    pub mapping: Option<String>,
    pub tag: String,
    pub timestamp: NaiveDateTime,
}

pub struct Detections {
    pub hits: Vec<Hit>,
    pub kind: Kind,
}

#[derive(Debug, Serialize)]
pub struct Detection<'a> {
    pub authors: &'a Vec<String>,
    pub group: &'a String,
    #[serde(flatten)]
    pub kind: &'a Kind,
    pub level: &'a String,
    pub name: &'a String,
    pub source: &'a String,
    pub status: &'a String,
    pub timestamp: String,
}

#[derive(Debug, Serialize)]
pub struct Document {
    pub kind: String,
    pub data: Json,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Kind {
    Aggregate { documents: Vec<Document> },
    Individual { document: Document },
}

pub trait Huntable {
    fn hits(
        &self,
        rules: &[Rule],
        exclusions: &HashSet<String>,
        group: &Group,
    ) -> Option<Vec<String>>;
}

#[derive(Default)]
pub struct HunterBuilder {
    mappings: Option<Vec<PathBuf>>,
    rules: Option<Vec<Rule>>,

    load_unknown: Option<bool>,
    local: Option<bool>,
    from: Option<NaiveDateTime>,
    skip_errors: Option<bool>,
    timezone: Option<Tz>,
    to: Option<NaiveDateTime>,
}

impl HunterBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn build(self) -> crate::Result<Hunter> {
        let mappings = match self.mappings {
            Some(mappings) => {
                let mut scratch = vec![];
                for mapping in mappings {
                    let mut file = File::open(mapping)?;
                    let mut content = String::new();
                    file.read_to_string(&mut content)?;
                    scratch.push(serde_yaml::from_str(&mut content)?);
                }
                scratch
            }
            None => vec![],
        };
        let rules = match self.rules {
            Some(rules) => rules,
            None => vec![],
        };

        let load_unknown = self.load_unknown.unwrap_or_default();
        let local = self.local.unwrap_or_default();
        let skip_errors = self.skip_errors.unwrap_or_default();

        Ok(Hunter {
            inner: HunterInner {
                mappings,
                rules,

                from: self.from.map(|d| DateTime::from_utc(d, Utc)),
                load_unknown,
                local,
                skip_errors,
                timezone: self.timezone,
                to: self.to.map(|d| DateTime::from_utc(d, Utc)),
            },
        })
    }

    pub fn from(mut self, datetime: NaiveDateTime) -> Self {
        self.from = Some(datetime);
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

    pub fn mappings(mut self, paths: Vec<PathBuf>) -> Self {
        self.mappings = Some(paths);
        self
    }

    pub fn rules(mut self, rules: Vec<Rule>) -> Self {
        self.rules = Some(rules);
        self
    }

    pub fn skip_errors(mut self, skip: bool) -> Self {
        self.skip_errors = Some(skip);
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

pub struct HunterInner {
    mappings: Vec<Mapping>,
    rules: Vec<Rule>,

    load_unknown: bool,
    local: bool,
    from: Option<DateTime<Utc>>,
    skip_errors: bool,
    timezone: Option<Tz>,
    to: Option<DateTime<Utc>>,
}

pub struct Hunter {
    inner: HunterInner,
}

impl Hunter {
    pub fn builder() -> HunterBuilder {
        HunterBuilder::new()
    }

    pub fn hunt(&self, file: &Path) -> crate::Result<Vec<Detections>> {
        let mut reader = Reader::load(file, self.inner.load_unknown, self.inner.skip_errors)?;
        let mut detections = vec![];
        for document in reader.documents() {
            let document = match document {
                Ok(document) => document,
                Err(e) => {
                    if self.inner.skip_errors {
                        continue;
                    }
                    return Err(e);
                }
            };

            // The logic is as follows, all rules except chainsaw ones need a mapping.

            // TODO: Handle chainsaw rules...

            for mapping in &self.inner.mappings {
                if mapping.kind != "evtx" {
                    continue;
                }

                let mut hits = vec![];
                for group in &mapping.groups {
                    // TODO: Default to RFC 3339
                    let timestamp = match &document {
                        Doc::Evtx(evtx) => {
                            match crate::evtx::Wrapper(&evtx.data).find(&group.timestamp) {
                                Some(value) => match value.as_str() {
                                    Some(timestamp) => match NaiveDateTime::parse_from_str(
                                        timestamp,
                                        "%Y-%m-%dT%H:%M:%S%.6fZ",
                                    ) {
                                        Ok(t) => t,
                                        Err(e) => {
                                            if self.inner.skip_errors {
                                                cs_eyellowln!(
                                                    "failed to parse timestamp '{}' - {}",
                                                    timestamp,
                                                    e,
                                                );
                                                continue;
                                            } else {
                                                anyhow::bail!(
                                                    "failed to parse timestamp '{}' - {}",
                                                    timestamp,
                                                    e
                                                );
                                            }
                                        }
                                    },
                                    None => continue,
                                },
                                None => continue,
                            }
                        }
                    };

                    if self.inner.from.is_some() || self.inner.to.is_some() {
                        // TODO: Not sure if this is correct...
                        let localised = if let Some(timezone) = self.inner.timezone {
                            let local = match timezone.from_local_datetime(&timestamp).single() {
                                Some(l) => l,
                                None => {
                                    if self.inner.skip_errors {
                                        cs_eyellowln!("failed to localise timestamp");
                                        continue;
                                    } else {
                                        anyhow::bail!("failed to localise timestamp");
                                    }
                                }
                            };
                            local.with_timezone(&Utc)
                        } else if self.inner.local {
                            match Utc.from_local_datetime(&timestamp).single() {
                                Some(l) => l,
                                None => {
                                    if self.inner.skip_errors {
                                        cs_eyellowln!("failed to localise timestamp");
                                        continue;
                                    } else {
                                        anyhow::bail!("failed to localise timestamp");
                                    }
                                }
                            }
                        } else {
                            DateTime::<Utc>::from_utc(timestamp, Utc)
                        };
                        // Check if event is older than start date marker
                        if let Some(sd) = self.inner.from {
                            if localised <= sd {
                                continue;
                            }
                        }
                        // Check if event is newer than end date marker
                        if let Some(ed) = self.inner.to {
                            if localised >= ed {
                                continue;
                            }
                        }
                    }
                    if let Some(tags) = match &document {
                        Doc::Evtx(evtx) => evtx.hits(&self.inner.rules, &mapping.exclusions, group),
                    } {
                        for tag in tags {
                            hits.push(Hit {
                                tag,
                                group: group.name.clone(),
                                mapping: Some(mapping.name.clone()),
                                timestamp,
                            });
                        }
                    }
                }

                if hits.is_empty() {
                    continue;
                }
                let data = match &document {
                    Doc::Evtx(evtx) => evtx.data.clone(),
                };
                detections.push(Detections {
                    hits,
                    kind: Kind::Individual {
                        document: Document {
                            kind: "evtx".to_owned(),
                            data,
                        },
                    },
                });
            }
        }
        Ok(detections)
    }

    pub fn mappings(&self) -> &Vec<Mapping> {
        &self.inner.mappings
    }

    pub fn rules(&self) -> &Vec<Rule> {
        &self.inner.rules
    }
}
