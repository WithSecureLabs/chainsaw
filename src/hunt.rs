use std::collections::{hash_map::DefaultHasher, HashMap, HashSet};
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::Read;
use std::path::{Path, PathBuf};

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use chrono_tz::Tz;
// https://github.com/rust-lang/rust/issues/74465
use once_cell::unsync::OnceCell;
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use tau_engine::{
    core::parser::{Expression, Pattern},
    Document as TauDocument, Value as Tau,
};
use uuid::Uuid;

use crate::file::{Document as File, Kind as FileKind, Reader};
use crate::rule::{
    chainsaw::{Aggregate, Container, Field, Filter, Format, Rule as Chainsaw},
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
                        let mapper = Mapper::from(rule.chainsaw.fields.clone());
                        hunts.push(Hunt {
                            id: uuid.clone(),

                            group: rule.chainsaw.group.clone(),
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
        if let Some(mut mappings) = self.mappings {
            mappings.sort();
            for mapping in mappings {
                let mut file = fs::File::open(mapping)?;
                let mut content = String::new();
                file.read_to_string(&mut content)?;
                let mut mapping: Mapping = serde_yaml::from_str(&mut content)?;
                mapping.groups.sort_by(|x, y| x.name.cmp(&y.name));
                for group in mapping.groups {
                    let mapper = Mapper::from(group.fields);
                    hunts.push(Hunt {
                        id: group.id,

                        group: group.name,
                        kind: HuntKind::Group {
                            exclusions: mapping.exclusions.clone(),
                            filter: group.filter,
                        },
                        timestamp: group.timestamp,

                        file: mapping.kind.clone(),
                        mapper,
                        rule: mapping.rules.clone(),
                    });
                }
            }
        }

        let load_unknown = self.load_unknown.unwrap_or_default();
        let local = self.local.unwrap_or_default();
        let skip_errors = self.skip_errors.unwrap_or_default();

        Ok(Hunter {
            inner: HunterInner {
                hunts,
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
    Full(HashMap<String, (String, Option<Container>)>),
}

pub struct Mapper {
    fields: Vec<Field>,
    kind: MapperKind,
}

impl Mapper {
    pub fn from(fields: Vec<Field>) -> Self {
        let mut fast = false;
        let mut full = false;
        for field in &fields {
            if field.container.is_some() {
                full = true;
                break;
            }
            if field.from != field.to {
                fast = true;
            }
        }
        let kind = if full {
            let mut map = HashMap::with_capacity(fields.len());
            for field in &fields {
                map.insert(
                    field.from.clone(),
                    (field.to.clone(), field.container.clone()),
                );
            }
            MapperKind::Full(map)
        } else if fast {
            let mut map = HashMap::with_capacity(fields.len());
            for field in &fields {
                map.insert(field.from.clone(), field.to.clone());
            }
            MapperKind::Fast(map)
        } else {
            MapperKind::None
        };
        Self { fields, kind }
    }

    pub fn fields(&self) -> &Vec<Field> {
        &self.fields
    }

    pub fn mapped<'a, D>(&'a self, document: &'a D) -> Mapped<'a>
    where
        D: TauDocument,
    {
        Mapped {
            cache: OnceCell::new(),
            document,
            mapper: self,
        }
    }
}

pub struct Mapped<'a> {
    cache: OnceCell<HashMap<String, Box<dyn TauDocument>>>,
    document: &'a dyn TauDocument,
    mapper: &'a Mapper,
}
impl<'a> TauDocument for Mapped<'a> {
    fn find(&self, key: &str) -> Option<Tau<'_>> {
        match &self.mapper.kind {
            MapperKind::None => self.document.find(key),
            MapperKind::Fast(map) => match map.get(key) {
                Some(v) => self.document.find(v),
                None => self.document.find(key),
            },
            MapperKind::Full(map) => match map.get(key) {
                Some((v, c)) => match c {
                    Some(container) => {
                        if let Some(cache) = self.cache.get() {
                            return cache.get(&container.field).and_then(|hit| hit.find(v));
                        }
                        // Due to referencing and ownership, we parse all containers at once, which
                        // then allows us to use a OnceCell.
                        let mut lookup = HashMap::new();
                        for field in &self.mapper.fields {
                            if let Some(container) = &field.container {
                                if !lookup.contains_key(&container.field) {
                                    let data = match self.document.find(&container.field) {
                                        Some(Tau::String(s)) => match container.format {
                                            Format::Json => {
                                                match serde_json::from_str::<Json>(&s) {
                                                    Ok(j) => Box::new(j) as Box<dyn TauDocument>,
                                                    Err(_) => continue,
                                                }
                                            }
                                        },
                                        _ => continue,
                                    };
                                    lookup.insert(container.field.clone(), data);
                                }
                            }
                        }
                        if let Err(_) = self.cache.set(lookup) {
                            panic!("cache is already set!");
                        }
                        if let Some(cache) = self.cache.get() {
                            return cache.get(&container.field).and_then(|hit| hit.find(v));
                        }
                        None
                    }
                    None => self.document.find(key),
                },
                None => self.document.find(key),
            },
        }
    }
}

pub struct Hunt {
    pub id: Uuid,
    pub group: String,
    pub kind: HuntKind,
    pub mapper: Mapper,
    pub timestamp: String,

    pub file: FileKind,
    pub rule: RuleKind,
}

impl Hunt {
    pub fn is_aggregation(&self) -> bool {
        if let HuntKind::Rule { aggregate, .. } = &self.kind {
            return aggregate.is_some();
        }
        false
    }
}

pub struct HunterInner {
    hunts: Vec<Hunt>,
    rules: HashMap<RuleKind, Vec<(Uuid, Chainsaw)>>,

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

                let mapped = hunt.mapper.mapped(&wrapper);

                let timestamp = match mapped.find(&hunt.timestamp) {
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
                            if tau_engine::core::solve(&filter, &mapped) {
                                for (rid, rule) in rules {
                                    if exclusions.contains(&rule.name) {
                                        continue;
                                    }
                                    let hit = match &rule.filter {
                                        Filter::Detection(detection) => {
                                            tau_engine::solve(&detection, &mapped)
                                        }
                                        Filter::Expression(expression) => {
                                            tau_engine::core::solve(&expression, &mapped)
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
                            Filter::Detection(detection) => tau_engine::solve(&detection, &mapped),
                            Filter::Expression(expression) => {
                                tau_engine::core::solve(&expression, &mapped)
                            }
                        };
                        if hit {
                            if let Some(aggregate) = aggregate {
                                files.insert(document_id.clone(), (document.clone(), timestamp));
                                let mut hasher = DefaultHasher::new();
                                for field in &aggregate.fields {
                                    if let Some(value) =
                                        mapped.find(&field).and_then(|s| s.to_string())
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
