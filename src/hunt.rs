use std::collections::{hash_map::DefaultHasher, HashMap, HashSet};
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::Read;
use std::path::{Path, PathBuf};

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use tau_engine::{
    core::parser::{Expression, Pattern},
    Document as TauDocument, Value as Tau,
};
use uuid::Uuid;

use crate::file::{Document as File, Kind as FileKind, Reader};
use crate::rule::{
    chainsaw::{Aggregate, Field, Filter, Rule as Chainsaw},
    Kind as RuleKind, Rule,
};

#[derive(Clone, Deserialize)]
pub struct Group {
    #[serde(skip, default = "Uuid::new_v4")]
    pub id: Uuid,
    pub fields: Vec<Field>,
    #[serde(deserialize_with = "crate::ext::tau::deserialize_expression")]
    pub filter: Expression,
    pub name: String,
    pub timestamp: String,
}

#[derive(Deserialize)]
pub struct Mapping {
    #[serde(default)]
    pub exclusions: HashSet<String>,
    pub groups: Vec<Group>,
    pub kind: FileKind,
    pub name: String,
    pub rules: RuleKind,
}

pub struct Hit {
    pub hunt: Uuid,
    pub rule: Uuid,
    pub timestamp: NaiveDateTime,
}

pub struct Detections {
    pub hits: Vec<Hit>,
    pub kind: Kind,
}

#[derive(Debug, Serialize)]
pub struct Document {
    pub kind: FileKind,
    pub data: Json,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Kind {
    Aggregate { documents: Vec<Document> },
    Individual { document: Document },
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
        let mut hunts = vec![];
        let rules = match self.rules {
            Some(mut rules) => {
                rules.sort_by(|x, y| x.chainsaw.name.cmp(&y.chainsaw.name));
                let mut map = HashMap::new();
                for rule in rules {
                    let uuid = Uuid::new_v4();
                    let rules = map.entry(rule.kind.clone()).or_insert(vec![]);
                    if &rule.kind == &RuleKind::Chainsaw {
                        let mapper = MapperKind::from(&rule.chainsaw.fields);
                        hunts.push(Hunt {
                            id: uuid.clone(),

                            group: rule.chainsaw.group.clone(),
                            headers: rule
                                .chainsaw
                                .fields
                                .iter()
                                .filter_map(|f| if f.visible { Some(&f.name) } else { None })
                                .cloned()
                                .collect(),
                            kind: HuntKind::Rule {
                                aggregate: rule.chainsaw.aggregate.clone(),
                                filter: rule.chainsaw.filter.clone(),
                            },
                            timestamp: rule.chainsaw.timestamp.clone(),

                            file: rule.chainsaw.kind.clone(),
                            mapper,
                            rule: rule.kind,
                        });
                    }
                    (*rules).push((uuid, rule.chainsaw));
                }
                map
            }
            None => HashMap::new(),
        };
        let mappings = match self.mappings {
            Some(mut mappings) => {
                mappings.sort();
                let mut scratch = vec![];
                for mapping in mappings {
                    let mut file = fs::File::open(mapping)?;
                    let mut content = String::new();
                    file.read_to_string(&mut content)?;
                    let mut mapping: Mapping = serde_yaml::from_str(&mut content)?;
                    mapping.groups.sort_by(|x, y| x.name.cmp(&y.name));
                    for group in &mapping.groups {
                        let mapper = MapperKind::from(&group.fields);
                        hunts.push(Hunt {
                            id: group.id.clone(),

                            group: group.name.clone(),
                            headers: group
                                .fields
                                .iter()
                                .filter_map(|f| if f.visible { Some(&f.name) } else { None })
                                .cloned()
                                .collect(),
                            kind: HuntKind::Group {
                                exclusions: mapping.exclusions.clone(),
                                filter: group.filter.clone(),
                            },
                            timestamp: group.timestamp.clone(),

                            file: mapping.kind.clone(),
                            mapper,
                            rule: mapping.rules.clone(),
                        });
                    }
                    scratch.push(mapping);
                }
                scratch
            }
            None => vec![],
        };

        let load_unknown = self.load_unknown.unwrap_or_default();
        let local = self.local.unwrap_or_default();
        let skip_errors = self.skip_errors.unwrap_or_default();

        Ok(Hunter {
            inner: HunterInner {
                hunts,
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

pub enum HuntKind {
    Group {
        exclusions: HashSet<String>,
        filter: Expression,
    },
    Rule {
        aggregate: Option<Aggregate>,
        filter: Filter,
    },
}

pub enum MapperKind {
    None,
    Fast(HashMap<String, String>),
    Full(HashMap<String, Field>),
}

impl MapperKind {
    pub fn from(fields: &Vec<Field>) -> Self {
        let mut fast = false;
        let mut full = false;
        for field in fields {
            if field.container.is_some() {
                full = true;
                break;
            }
            if field.from != field.to {
                fast = true;
            }
        }
        if full {
            let mut map = HashMap::with_capacity(fields.len());
            for field in fields {
                map.insert(field.from.clone(), field.clone());
            }
            MapperKind::Full(map)
        } else if fast {
            let mut map = HashMap::with_capacity(fields.len());
            for field in fields {
                map.insert(field.from.clone(), field.to.clone());
            }
            MapperKind::Fast(map)
        } else {
            MapperKind::None
        }
    }
}

pub struct Hunt {
    pub id: Uuid,
    pub group: String,
    pub headers: Vec<String>,
    pub kind: HuntKind,
    pub timestamp: String,

    pub file: FileKind,
    pub mapper: MapperKind,
    pub rule: RuleKind,
}

pub struct HunterInner {
    hunts: Vec<Hunt>,
    mappings: Vec<Mapping>,
    rules: HashMap<RuleKind, Vec<(Uuid, Chainsaw)>>,

    load_unknown: bool,
    local: bool,
    from: Option<DateTime<Utc>>,
    skip_errors: bool,
    timezone: Option<Tz>,
    to: Option<DateTime<Utc>>,
}

//pub struct Mapper<'a>(&'a HashMap<String, String>, &'a dyn TauDocument);
pub struct Mapper<'a>(pub &'a MapperKind, pub &'a dyn TauDocument);
impl<'a> TauDocument for Mapper<'a> {
    fn find(&self, key: &str) -> Option<Tau<'_>> {
        match &self.0 {
            MapperKind::None => self.1.find(key),
            MapperKind::Fast(map) => match map.get(key) {
                Some(v) => self.1.find(v),
                None => self.1.find(key),
            },
            //MapperKind::Full(map) => unimplemented!(),
            MapperKind::Full(map) => self.1.find(key),
        }
    }
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
        let kind = reader.kind();
        // This can be optimised better ;)
        let mut detections = vec![];
        let mut aggregates: HashMap<Uuid, (&Aggregate, HashMap<u64, Vec<Uuid>>)> = HashMap::new();
        let mut files: HashMap<Uuid, (File, NaiveDateTime)> = HashMap::new();
        for document in reader.documents() {
            let document_id = Uuid::new_v4();
            let document = match document {
                Ok(document) => document,
                Err(e) => {
                    if self.inner.skip_errors {
                        continue;
                    }
                    return Err(e);
                }
            };
            let wrapper = match &document {
                File::Evtx(evtx) => crate::evtx::Wrapper(&evtx.data),
            };
            let mut hits = vec![];
            for hunt in &self.inner.hunts {
                if hunt.file != kind {
                    continue;
                }

                let mapper = Mapper(&hunt.mapper, &wrapper);

                let timestamp = match mapper.find(&hunt.timestamp) {
                    Some(value) => match value.as_str() {
                        Some(timestamp) => {
                            match NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%dT%H:%M:%S%.6fZ")
                            {
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
                            }
                        }
                        None => continue,
                    },
                    None => continue,
                };

                if self.skip(timestamp)? {
                    continue;
                }

                match &hunt.kind {
                    HuntKind::Group { exclusions, filter } => {
                        if let Some(rules) = self.inner.rules.get(&hunt.rule) {
                            if tau_engine::core::solve(&filter, &mapper) {
                                for (rid, rule) in rules {
                                    if exclusions.contains(&rule.name) {
                                        continue;
                                    }
                                    let hit = match &rule.filter {
                                        Filter::Detection(detection) => {
                                            tau_engine::solve(&detection, &mapper)
                                        }
                                        Filter::Expression(expression) => {
                                            tau_engine::core::solve(&expression, &mapper)
                                        }
                                    };
                                    if hit {
                                        hits.push(Hit {
                                            hunt: hunt.id.clone(),
                                            rule: rid.clone(),
                                            timestamp,
                                        });
                                    }
                                }
                            }
                        }
                    }
                    HuntKind::Rule { aggregate, filter } => {
                        let hit = match &filter {
                            Filter::Detection(detection) => tau_engine::solve(&detection, &mapper),
                            Filter::Expression(expression) => {
                                tau_engine::core::solve(&expression, &mapper)
                            }
                        };
                        if hit {
                            if let Some(aggregate) = aggregate {
                                files.insert(document_id.clone(), (document.clone(), timestamp));
                                let mut hasher = DefaultHasher::new();
                                for field in &aggregate.fields {
                                    if let Some(value) =
                                        mapper.find(&field).and_then(|s| s.to_string())
                                    {
                                        value.hash(&mut hasher);
                                    }
                                }
                                let id = hasher.finish();
                                let aggregates = aggregates
                                    .entry(hunt.id)
                                    .or_insert((&aggregate, HashMap::new()));
                                let docs = aggregates.1.entry(id).or_insert(vec![]);
                                docs.push(document_id.clone());
                            } else {
                                hits.push(Hit {
                                    hunt: hunt.id.clone(),
                                    rule: hunt.id.clone(),
                                    timestamp,
                                });
                            }
                        }
                    }
                }
            }
            if !hits.is_empty() {
                let data = match &document {
                    File::Evtx(evtx) => evtx.data.clone(),
                };
                detections.push(Detections {
                    hits,
                    kind: Kind::Individual {
                        document: Document {
                            kind: kind.clone(),
                            data,
                        },
                    },
                });
            }
        }
        for (id, (aggregate, docs)) in aggregates {
            for ids in docs.values() {
                let hit = match aggregate.count {
                    Pattern::Equal(i) => (i as usize) == ids.len(),
                    Pattern::GreaterThan(i) => (i as usize) > ids.len(),
                    Pattern::GreaterThanOrEqual(i) => (i as usize) >= ids.len(),
                    Pattern::LessThan(i) => (i as usize) < ids.len(),
                    Pattern::LessThanOrEqual(i) => (i as usize) <= ids.len(),
                    _ => false,
                };
                if hit {
                    let mut documents = Vec::with_capacity(ids.len());
                    let mut timestamps = Vec::with_capacity(ids.len());
                    for id in ids {
                        let (document, timestamp) = files.get(&id).expect("could not get document");
                        let data = match &document {
                            File::Evtx(evtx) => evtx.data.clone(),
                        };
                        documents.push(Document {
                            kind: kind.clone(),
                            data,
                        });
                        timestamps.push(timestamp.clone());
                    }
                    timestamps.sort();
                    detections.push(Detections {
                        hits: vec![Hit {
                            hunt: id.clone(),
                            rule: id.clone(),
                            timestamp: timestamps
                                .into_iter()
                                .next()
                                .expect("failed to get timestamp"),
                        }],
                        kind: Kind::Aggregate { documents },
                    });
                }
            }
        }
        Ok(detections)
    }

    pub fn hunts(&self) -> &Vec<Hunt> {
        &self.inner.hunts
    }

    pub fn mappings(&self) -> &Vec<Mapping> {
        &self.inner.mappings
    }

    pub fn rules(&self) -> &HashMap<RuleKind, Vec<(Uuid, Chainsaw)>> {
        &self.inner.rules
    }

    fn skip(&self, timestamp: NaiveDateTime) -> crate::Result<bool> {
        if self.inner.from.is_some() || self.inner.to.is_some() {
            // TODO: Not sure if this is correct...
            let localised = if let Some(timezone) = self.inner.timezone {
                let local = match timezone.from_local_datetime(&timestamp).single() {
                    Some(l) => l,
                    None => {
                        if self.inner.skip_errors {
                            cs_eyellowln!("failed to localise timestamp");
                            return Ok(true);
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
                            return Ok(true);
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
                    return Ok(true);
                }
            }
            // Check if event is newer than end date marker
            if let Some(ed) = self.inner.to {
                if localised >= ed {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}
