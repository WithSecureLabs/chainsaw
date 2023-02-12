use std::borrow::Cow;
use std::collections::{hash_map::DefaultHasher, BTreeMap, HashMap, HashSet};
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::Read;
use std::path::{Path, PathBuf};

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use chrono_tz::Tz;
// https://github.com/rust-lang/rust/issues/74465
use once_cell::sync::OnceCell;
use rayon::prelude::*;
use serde::{
    ser::{SerializeStruct, Serializer},
    Deserialize, Serialize,
};
use serde_json::Value as Json;
use tau_engine::{
    core::parser::{Expression, ModSym, Pattern},
    Document as TauDocument, Value as Tau,
};
use uuid::Uuid;

use crate::file::{Document as File, Kind as FileKind, Reader};
use crate::rule::{
    chainsaw::{Container, Field, Format},
    Aggregate, Filter, Kind as RuleKind, Rule,
};
use crate::value::Value;

#[derive(Clone, Deserialize)]
pub struct Precondition {
    #[serde(rename = "for")]
    for_: HashMap<String, String>,
    #[serde(deserialize_with = "crate::ext::tau::deserialize_expression")]
    pub filter: Expression,
}

#[derive(Clone, Deserialize)]
pub struct Extensions {
    #[serde(default)]
    preconditions: Option<Vec<Precondition>>,
}

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
    #[serde(default)]
    pub extensions: Option<Extensions>,
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

pub struct Detections<'a> {
    pub hits: Vec<Hit>,
    pub kind: Kind<'a>,
}

//#[derive(Debug, Serialize)]
#[derive(Debug)]
pub struct Document<'a> {
    pub kind: FileKind,
    pub path: &'a Path,
    // NOTE: Serialised Value using bincode.
    pub data: Vec<u8>,
}

impl<'a> Serialize for Document<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // 3 is the number of fields in the struct.
        let mut state = serializer.serialize_struct("Document", 3)?;
        state.serialize_field("kind", &self.kind)?;
        state.serialize_field("path", &self.path)?;
        let value: Value = bincode::deserialize(&self.data).expect("could not decompress");
        let json = Json::from(value);
        state.serialize_field("data", &json)?;
        state.end()
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Kind<'a> {
    Aggregate { documents: Vec<Document<'a>> },
    Individual { document: Document<'a> },
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
                rules.sort_by(|x, y| x.name().cmp(y.name()));
                let mut map = BTreeMap::new();
                for rule in rules {
                    let uuid = Uuid::new_v4();
                    if let Rule::Chainsaw(rule) = &rule {
                        let mapper = Mapper::from(rule.fields.clone());
                        hunts.push(Hunt {
                            id: uuid,

                            group: rule.group.clone(),
                            kind: HuntKind::Rule {
                                aggregate: rule.aggregate.clone(),
                                filter: rule.filter.clone(),
                            },
                            timestamp: rule.timestamp.clone(),

                            file: rule.kind.clone(),
                            mapper,
                        });
                    }
                    map.insert(uuid, rule);
                }
                map
            }
            None => BTreeMap::new(),
        };
        if let Some(mut mappings) = self.mappings {
            mappings.sort();
            for mapping in mappings {
                let mut file = match fs::File::open(mapping) {
                    Ok(a) => a,
                    Err(e) => anyhow::bail!("Error loading specified mapping file - {}", e),
                };
                let mut content = String::new();
                file.read_to_string(&mut content)?;
                let mut mapping: Mapping = match serde_yaml::from_str(&content) {
                    Ok(a) => a,
                    Err(e) => anyhow::bail!("Provided mapping file is invalid - {}", e),
                };
                if let RuleKind::Chainsaw = mapping.rules {
                    anyhow::bail!("Chainsaw rules do not support mappings");
                }
                let mut preconds = HashMap::new();
                if let Some(extensions) = &mapping.extensions {
                    if let Some(preconditions) = &extensions.preconditions {
                        for precondition in preconditions {
                            for (rid, rule) in &rules {
                                if let Rule::Sigma(sigma) = rule {
                                    // FIXME: How do we handle multiple matches, for now we just take
                                    // the latest, we chould probably just combine them into an AND?
                                    if precondition.for_.is_empty() {
                                        continue;
                                    }
                                    let mut matched = true;
                                    for (f, v) in &precondition.for_ {
                                        match sigma.find(&f) {
                                            Some(value) => {
                                                if value.as_str() != Some(v.as_str()) {
                                                    matched = false;
                                                    break;
                                                }
                                            }
                                            None => {
                                                matched = false;
                                                break;
                                            }
                                        }
                                    }
                                    if matched {
                                        preconds.insert(*rid, precondition.filter.clone());
                                    }
                                }
                            }
                        }
                    }
                }
                mapping.groups.sort_by(|x, y| x.name.cmp(&y.name));
                for group in mapping.groups {
                    let mapper = Mapper::from(group.fields);
                    hunts.push(Hunt {
                        id: group.id,

                        group: group.name,
                        kind: HuntKind::Group {
                            exclusions: mapping.exclusions.clone(),
                            filter: group.filter,
                            kind: mapping.rules.clone(),
                            preconditions: preconds.clone(),
                        },
                        timestamp: group.timestamp,

                        file: mapping.kind.clone(),
                        mapper,
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
        kind: RuleKind,
        preconditions: HashMap<Uuid, Expression>,
    },
    Rule {
        aggregate: Option<Aggregate>,
        filter: Filter,
    },
}

pub enum MapperKind {
    None,
    Fast(HashMap<String, String>),
    Full(HashMap<String, (String, Option<Container>, Option<ModSym>)>),
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
            if field.cast.is_some() || field.container.is_some() {
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
                    (
                        field.to.clone(),
                        field.container.clone(),
                        field.cast.clone(),
                    ),
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
                Some((v, Some(container), None)) => {
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
                                        Format::Json => match serde_json::from_str::<Json>(&s) {
                                            Ok(j) => Box::new(j) as Box<dyn TauDocument>,
                                            Err(_) => continue,
                                        },
                                    },
                                    _ => continue,
                                };
                                lookup.insert(container.field.clone(), data);
                            }
                        }
                    }
                    if self.cache.set(lookup).is_err() {
                        panic!("cache is already set!");
                    }
                    if let Some(cache) = self.cache.get() {
                        return cache.get(&container.field).and_then(|hit| hit.find(v));
                    }
                    None
                }
                Some((v, None, Some(sym))) => match sym {
                    ModSym::Int => match self.document.find(v) {
                        Some(res) => {
                            // NOTE: We only parse string into i64 for now, we leave the other
                            // types alone...
                            if let Tau::String(s) = &res {
                                if let Ok(i) = str::parse::<i64>(s) {
                                    return Some(Tau::Int(i));
                                }
                            }
                            Some(res)
                        }
                        res => res,
                    },
                    ModSym::Str => match self.document.find(v) {
                        Some(value) => value.to_string().map(|s| Tau::String(Cow::Owned(s))),
                        res => res,
                    },
                    _ => unreachable!(),
                },
                Some((v, None, None)) => self.document.find(v),
                _ => self.document.find(key),
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
}

impl Hunt {
    pub fn is_aggregation(&self) -> bool {
        match &self.kind {
            HuntKind::Group { .. } => true,
            HuntKind::Rule { aggregate, .. } => aggregate.is_some(),
        }
    }
}

pub struct HunterInner {
    hunts: Vec<Hunt>,
    rules: BTreeMap<Uuid, Rule>,

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

    pub fn hunt<'a>(&'a self, file: &'a Path) -> crate::Result<Vec<Detections>> {
        let mut reader = Reader::load(file, self.inner.load_unknown, self.inner.skip_errors)?;
        let kind = reader.kind();
        // This can be optimised better ;)
        let mut detections = vec![];
        let mut aggregates: HashMap<(Uuid, Uuid), (&Aggregate, HashMap<u64, Vec<Uuid>>)> =
            HashMap::new();
        let mut files: HashMap<Uuid, (File, NaiveDateTime)> = HashMap::new();
        for document in reader.documents() {
            let document_id = Uuid::new_v4();
            let document = match document {
                Ok(document) => document,
                Err(e) => {
                    if self.inner.skip_errors {
                        cs_eyellowln!(
                            "[!] failed to parse document '{}' - {}\n",
                            file.display(),
                            e
                        );
                        continue;
                    }
                    return Err(anyhow!(format!("{} in {}", e, file.display())));
                }
            };
            let mut hits = vec![];
            for hunt in &self.inner.hunts {
                if hunt.file != kind {
                    continue;
                }

                let wrapper;
                let mapped = match &document {
                    File::Evtx(evtx) => {
                        wrapper = crate::evtx::Wrapper(&evtx.data);
                        hunt.mapper.mapped(&wrapper)
                    }
                    File::Json(json) => hunt.mapper.mapped(json),
                    File::Mft(mft) => hunt.mapper.mapped(mft),
                    File::Xml(xml) => hunt.mapper.mapped(xml),
                };

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
                    HuntKind::Group {
                        exclusions,
                        filter,
                        kind,
                        preconditions,
                    } => {
                        if tau_engine::core::solve(filter, &mapped) {
                            let matches = &self
                                .inner
                                .rules
                                .par_iter()
                                .filter_map(|(rid, rule)| {
                                    if !rule.is_kind(kind) {
                                        return None;
                                    }
                                    if exclusions.contains(rule.name()) {
                                        return None;
                                    }
                                    if let Some(filter) = preconditions.get(rid) {
                                        if !tau_engine::core::solve(filter, &mapped) {
                                            return None;
                                        }
                                    }
                                    if rule.solve(&mapped) {
                                        Some((*rid, rule))
                                    } else {
                                        None
                                    }
                                })
                                .collect::<Vec<(_, _)>>();
                            for (rid, rule) in matches {
                                if let Some(aggregate) = &rule.aggregate() {
                                    files.insert(document_id, (document.clone(), timestamp));
                                    let mut hasher = DefaultHasher::new();
                                    let mut skip = false;
                                    for field in &aggregate.fields {
                                        if let Some(value) =
                                            mapped.find(field).and_then(|s| s.to_string())
                                        {
                                            value.hash(&mut hasher);
                                        } else {
                                            skip = true;
                                            break;
                                        }
                                    }
                                    if skip {
                                        continue;
                                    }
                                    let id = hasher.finish();
                                    let aggregates = aggregates
                                        .entry((hunt.id, *rid))
                                        .or_insert((aggregate, HashMap::new()));
                                    let docs = aggregates.1.entry(id).or_insert(vec![]);
                                    docs.push(document_id);
                                } else {
                                    hits.push(Hit {
                                        hunt: hunt.id,
                                        rule: *rid,
                                        timestamp,
                                    });
                                }
                            }
                        }
                    }
                    HuntKind::Rule { aggregate, filter } => {
                        let hit = match &filter {
                            Filter::Detection(detection) => tau_engine::solve(detection, &mapped),
                            Filter::Expression(expression) => {
                                tau_engine::core::solve(expression, &mapped)
                            }
                        };
                        if hit {
                            if let Some(aggregate) = aggregate {
                                files.insert(document_id, (document.clone(), timestamp));
                                let mut hasher = DefaultHasher::new();
                                let mut skip = false;
                                for field in &aggregate.fields {
                                    if let Some(value) =
                                        mapped.find(field).and_then(|s| s.to_string())
                                    {
                                        value.hash(&mut hasher);
                                    } else {
                                        skip = true;
                                        break;
                                    }
                                }
                                if skip {
                                    continue;
                                }
                                let id = hasher.finish();
                                let aggregates = aggregates
                                    .entry((hunt.id, hunt.id))
                                    .or_insert((aggregate, HashMap::new()));
                                let docs = aggregates.1.entry(id).or_insert(vec![]);
                                docs.push(document_id);
                            } else {
                                hits.push(Hit {
                                    hunt: hunt.id,
                                    rule: hunt.id,
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
                    File::Mft(mft) => mft.clone(),
                    File::Json(json) => json.clone(),
                    File::Xml(xml) => xml.clone(),
                };
                detections.push(Detections {
                    hits,
                    kind: Kind::Individual {
                        document: Document {
                            kind: kind.clone(),
                            path: &file,
                            data: bincode::serialize(&Value::from(data))?,
                        },
                    },
                });
            }
        }
        for ((hid, rid), (aggregate, docs)) in aggregates {
            for ids in docs.values() {
                let hit = match aggregate.count {
                    Pattern::Equal(i) => ids.len() == (i as usize),
                    Pattern::GreaterThan(i) => ids.len() > (i as usize),
                    Pattern::GreaterThanOrEqual(i) => ids.len() >= (i as usize),
                    Pattern::LessThan(i) => ids.len() < (i as usize),
                    Pattern::LessThanOrEqual(i) => ids.len() <= (i as usize),
                    _ => false,
                };
                if hit {
                    let mut documents = Vec::with_capacity(ids.len());
                    let mut timestamps = Vec::with_capacity(ids.len());
                    for id in ids {
                        let (document, timestamp) = files.get(id).expect("could not get document");
                        let data = match &document {
                            File::Evtx(evtx) => evtx.data.clone(),
                            File::Mft(mft) => mft.clone(),
                            File::Json(json) => json.clone(),
                            File::Xml(xml) => xml.clone(),
                        };
                        documents.push(Document {
                            kind: kind.clone(),
                            path: &file,
                            data: bincode::serialize(&Value::from(data))?,
                        });
                        timestamps.push(*timestamp);
                    }
                    timestamps.sort();
                    detections.push(Detections {
                        hits: vec![Hit {
                            hunt: hid,
                            rule: rid,
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

    pub fn extensions(&self) -> HashSet<String> {
        let mut extensions = HashSet::new();
        for rule in &self.inner.rules {
            if let Some(e) = FileKind::extensions(rule.1.types()) {
                extensions.extend(e.iter().cloned());
            }
        }
        for hunt in &self.inner.hunts {
            if let Some(e) = FileKind::extensions(&hunt.file) {
                extensions.extend(e.iter().cloned());
            }
        }
        extensions
    }

    pub fn hunts(&self) -> &Vec<Hunt> {
        &self.inner.hunts
    }

    pub fn rules(&self) -> &BTreeMap<Uuid, Rule> {
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
