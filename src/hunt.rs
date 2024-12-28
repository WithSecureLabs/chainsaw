use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::hash::{BuildHasherDefault, Hash, Hasher};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use chrono_tz::Tz;
// https://github.com/rust-lang/rust/issues/74465
use once_cell::sync::OnceCell;
use rayon::prelude::*;
use rustc_hash::{FxBuildHasher, FxHashMap, FxHasher};
use serde::{
    ser::{SerializeStruct, Serializer},
    Deserialize, Serialize,
};
use serde_json::{value::RawValue, Value as Json};
use smallvec::SmallVec;
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
    pub rules: RuleKind,
}

pub struct Hit {
    pub hunt: Uuid,
    pub rule: Uuid,
    pub timestamp: NaiveDateTime,
}

pub struct Detections<'a> {
    pub hits: SmallVec<[Hit; 1]>,
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

impl Serialize for Document<'_> {
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
pub struct RawDocument<'a> {
    pub kind: FileKind,
    pub path: &'a Path,
    #[serde(borrow)]
    pub data: Option<&'a RawValue>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Kind<'a> {
    Aggregate {
        documents: Vec<Document<'a>>,
    },
    Individual {
        document: Document<'a>,
    },
    Cached {
        document: RawDocument<'a>,
        #[serde(skip)]
        offset: usize,
        #[serde(skip)]
        size: usize,
    },
}

#[derive(Default)]
pub struct HunterBuilder {
    mappings: Option<Vec<PathBuf>>,
    rules: Option<Vec<Rule>>,

    load_unknown: Option<bool>,
    local: Option<bool>,
    preprocess: Option<bool>,
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
        cs_trace!("[*] Loading rules...");
        let mut rules = match self.rules {
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
            cs_trace!("[*] Loading mappings...");
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
                let mut preconds = FxHashMap::default();
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
                                        match sigma.find(f) {
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
                    let mut exclusions = HashSet::<Uuid, BuildHasherDefault<FxHasher>>::default();
                    for (rid, rule) in &rules {
                        if mapping.exclusions.contains(rule.name()) {
                            exclusions.insert(*rid);
                        }
                    }
                    let mapper = Mapper::from(group.fields);
                    // FIXME: Due to how file types are handled we lose jsonl, as its file type
                    // internally here is json, so we coerce it for now... Putting a match here
                    // will make sure we don't make this mistake again until its handled properly.
                    let file = match mapping.kind {
                        FileKind::Evtx => FileKind::Evtx,
                        FileKind::Hve => FileKind::Hve,
                        FileKind::Json => FileKind::Json,
                        FileKind::Jsonl => FileKind::Json,
                        FileKind::Mft => FileKind::Mft,
                        FileKind::Xml => FileKind::Xml,
                        FileKind::Esedb => FileKind::Esedb,
                        FileKind::Unknown => unreachable!(),
                    };
                    hunts.push(Hunt {
                        id: group.id,

                        group: group.name,
                        kind: HuntKind::Group {
                            exclusions,
                            filter: group.filter,
                            kind: mapping.rules.clone(),
                            preconditions: preconds.clone(),
                        },
                        timestamp: group.timestamp,

                        file,
                        mapper,
                    });
                }
            }
        }

        let load_unknown = self.load_unknown.unwrap_or_default();
        let local = self.local.unwrap_or_default();
        let preprocess = self.preprocess.unwrap_or_default();
        let skip_errors = self.skip_errors.unwrap_or_default();

        let mut fields = vec![];
        if preprocess {
            cs_trace!("[*] Preprocessing...");
            let mut keys = HashSet::new();
            for hunt in &hunts {
                keys.insert(hunt.timestamp.clone());
                match &hunt.kind {
                    HuntKind::Rule { aggregate, filter } => {
                        if let Some(a) = &aggregate {
                            keys.extend(a.fields.iter().cloned());
                        }
                        match &filter {
                            Filter::Detection(d) => {
                                keys.extend(crate::ext::tau::extract_fields(&d.expression));
                            }
                            Filter::Expression(e) => {
                                keys.extend(crate::ext::tau::extract_fields(e));
                            }
                        }
                    }
                    HuntKind::Group {
                        filter,
                        preconditions,
                        ..
                    } => {
                        keys.extend(crate::ext::tau::extract_fields(filter));
                        for precondition in preconditions.values() {
                            keys.extend(crate::ext::tau::extract_fields(precondition));
                        }
                    }
                }
            }
            for rule in rules.values() {
                match rule {
                    Rule::Chainsaw(c) => {
                        if let Some(a) = &c.aggregate {
                            keys.extend(a.fields.iter().cloned());
                        }
                        match &c.filter {
                            Filter::Detection(d) => {
                                keys.extend(crate::ext::tau::extract_fields(&d.expression));
                            }
                            Filter::Expression(e) => {
                                keys.extend(crate::ext::tau::extract_fields(e));
                            }
                        }
                    }
                    Rule::Sigma(s) => {
                        if let Some(a) = &s.aggregate {
                            keys.extend(a.fields.iter().cloned());
                        }
                        keys.extend(crate::ext::tau::extract_fields(&s.tau.detection.expression));
                    }
                }
            }

            let mut lookup = HashMap::with_capacity(keys.len());
            for (i, f) in keys.into_iter().enumerate() {
                let x = (i / 255) as u8;
                let y = (i % 255) as u8;
                let mut bytes = Vec::with_capacity(x as usize + 1);
                #[allow(clippy::same_item_push)]
                for _ in 0..x {
                    bytes.push(255);
                }
                bytes.push(y);
                let field: String = unsafe { String::from_utf8_unchecked(bytes) };
                lookup.insert(f.clone(), field);
                fields.push(f);
            }
            hunts = hunts
                .into_iter()
                .map(|mut h| {
                    h.timestamp = lookup
                        .get(&h.timestamp)
                        .expect("could not get field")
                        .to_owned();
                    h.kind = match h.kind {
                        HuntKind::Rule {
                            mut aggregate,
                            mut filter,
                        } => {
                            if let Some(a) = aggregate.as_mut() {
                                a.fields = a
                                    .fields
                                    .iter()
                                    .map(|f| lookup.get(f).expect("could not get field"))
                                    .cloned()
                                    .collect();
                            }
                            filter = match filter {
                                Filter::Detection(mut d) => {
                                    d.expression =
                                        crate::ext::tau::update_fields(d.expression, &lookup);
                                    Filter::Detection(d)
                                }
                                Filter::Expression(e) => {
                                    Filter::Expression(crate::ext::tau::update_fields(e, &lookup))
                                }
                            };
                            HuntKind::Rule { aggregate, filter }
                        }
                        HuntKind::Group {
                            exclusions,
                            filter,
                            kind,
                            preconditions,
                        } => HuntKind::Group {
                            exclusions,
                            filter: crate::ext::tau::update_fields(filter, &lookup),
                            kind,
                            preconditions: preconditions
                                .into_iter()
                                .map(|(i, p)| (i, crate::ext::tau::update_fields(p, &lookup)))
                                .collect(),
                        },
                    };
                    h
                })
                .collect();
            rules = rules
                .into_iter()
                .map(|(i, r)| {
                    let r = match r {
                        Rule::Chainsaw(mut c) => {
                            if let Some(a) = c.aggregate.as_mut() {
                                a.fields = a
                                    .fields
                                    .iter()
                                    .map(|f| lookup.get(f).expect("could not get field"))
                                    .cloned()
                                    .collect();
                            }
                            c.filter = match c.filter {
                                Filter::Detection(mut d) => {
                                    d.expression =
                                        crate::ext::tau::update_fields(d.expression, &lookup);
                                    Filter::Detection(d)
                                }
                                Filter::Expression(e) => {
                                    Filter::Expression(crate::ext::tau::update_fields(e, &lookup))
                                }
                            };
                            Rule::Chainsaw(c)
                        }
                        Rule::Sigma(mut s) => {
                            if let Some(a) = s.aggregate.as_mut() {
                                a.fields = a
                                    .fields
                                    .iter()
                                    .map(|f| lookup.get(f).expect("could not get field"))
                                    .cloned()
                                    .collect();
                            }
                            s.tau.detection.expression =
                                crate::ext::tau::update_fields(s.tau.detection.expression, &lookup);
                            Rule::Sigma(s)
                        }
                    };
                    (i, r)
                })
                .collect();
        }

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

        Ok(Hunter {
            inner: HunterInner {
                hunts,
                fields,
                rules,

                from,
                load_unknown,
                preprocess,
                skip_errors,
                to,
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

    pub fn preprocess(mut self, preprocess: bool) -> Self {
        self.preprocess = Some(preprocess);
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
        exclusions: HashSet<Uuid, BuildHasherDefault<FxHasher>>,
        filter: Expression,
        kind: RuleKind,
        preconditions: FxHashMap<Uuid, Expression>,
    },
    Rule {
        aggregate: Option<Aggregate>,
        filter: Filter,
    },
}

pub enum MapperKind {
    None,
    Fast(FxHashMap<String, String>),
    Full(FxHashMap<String, (String, Option<Container>, Option<ModSym>)>),
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
            cs_trace!("[*] Using mapper in full mode");
            let mut map = FxHashMap::with_capacity_and_hasher(fields.len(), FxBuildHasher);
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
            cs_trace!("[*] Using mapper in fast mode");
            let mut map = FxHashMap::with_capacity_and_hasher(fields.len(), FxBuildHasher);
            for field in &fields {
                map.insert(field.from.clone(), field.to.clone());
            }
            MapperKind::Fast(map)
        } else {
            cs_trace!("[*] Using mapper in bypass mode");
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
    cache: OnceCell<FxHashMap<String, Box<dyn TauDocument>>>,
    document: &'a dyn TauDocument,
    mapper: &'a Mapper,
}
impl TauDocument for Mapped<'_> {
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
                    let mut lookup = FxHashMap::default();
                    for field in &self.mapper.fields {
                        if let Some(container) = &field.container {
                            if !lookup.contains_key(&container.field) {
                                let data = match self.document.find(&container.field) {
                                    Some(Tau::String(s)) => match container.format {
                                        Format::Json => match serde_json::from_str::<Json>(&s) {
                                            Ok(j) => Box::new(j) as Box<dyn TauDocument>,
                                            Err(_) => continue,
                                        },
                                        Format::Kv {
                                            ref delimiter,
                                            ref separator,
                                            trim,
                                        } => {
                                            let mut map = FxHashMap::default();
                                            for item in s.split(delimiter) {
                                                let cleaned = if trim { item.trim() } else { item };
                                                if let Some((k, v)) = cleaned.split_once(separator)
                                                {
                                                    map.insert(k.to_owned(), v.to_owned());
                                                }
                                            }
                                            Box::new(map) as Box<dyn TauDocument>
                                        }
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

struct Cache<'a> {
    cache: Option<Vec<Option<Tau<'a>>>>,
    mapped: &'a Mapped<'a>,
}
impl TauDocument for Cache<'_> {
    #[inline(always)]
    fn find(&self, key: &str) -> Option<Tau<'_>> {
        if let Some(cache) = &self.cache {
            cs_trace!("[*] Using cache for key lookup - {}", key);
            let index = key.bytes().fold(0, |acc, x| acc + (x as usize));
            cache[index].clone()
        } else {
            self.mapped.find(key)
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
    fields: Vec<String>,
    rules: BTreeMap<Uuid, Rule>,

    load_unknown: bool,
    preprocess: bool,
    from: Option<DateTime<Utc>>,
    skip_errors: bool,
    to: Option<DateTime<Utc>>,
}

pub struct Hunter {
    inner: HunterInner,
}

impl Hunter {
    pub fn builder() -> HunterBuilder {
        HunterBuilder::new()
    }

    pub fn hunt<'a>(
        &'a self,
        file: &'a Path,
        cache: &Option<std::fs::File>,
    ) -> crate::Result<Vec<Detections<'a>>> {
        let mut reader = Reader::load(
            file,
            self.inner.load_unknown,
            self.inner.skip_errors,
            true,
            None,
        )?;

        let kind = reader.kind();
        #[allow(clippy::type_complexity)]
        let aggregates: Mutex<
            FxHashMap<(Uuid, Uuid), (&Aggregate, FxHashMap<u64, Vec<Uuid>>)>,
        > = Mutex::new(FxHashMap::default());
        let files: Mutex<FxHashMap<Uuid, (Value, NaiveDateTime)>> =
            Mutex::new(FxHashMap::default());
        let offset = Mutex::new(0);
        let mut detections = reader
            .documents()
            .par_bridge()
            .filter_map(|document| {
                let document_id = Uuid::new_v4();
                let document = match document {
                    Ok(document) => document,
                    Err(e) => {
                        if self.inner.skip_errors {
                            cs_eyellowln!(
                                "[!] failed to parse document '{}' - {} - use --skip-errors to continue...\n",
                                file.display(),
                                e
                            );
                            return None;
                        }
                        return Some(Err(anyhow!(format!("{} in {}", e, file.display()))));
                    }
                };
                let (kind, value): (FileKind, Value) = match document {
                    File::Evtx(evtx) => {
                        cs_trace!(
                            "[*] Hunting through document {} - {:?}",
                            document_id,
                            evtx.data
                        );
                        (FileKind::Evtx, evtx.data.into())
                    }
                    File::Hve(hve) => {
                        cs_trace!("[*] Hunting through document {} - {:?}", document_id, hve);
                        (FileKind::Hve, hve.into())
                    }
                    File::Json(json) => {
                        cs_trace!("[*] Hunting through document {} - {:?}", document_id, json);
                        (FileKind::Json, json.into())
                    }
                    File::Mft(mft) => {
                        cs_trace!("[*] Hunting through document {} - {:?}", document_id, mft);
                        (FileKind::Mft, mft.into())
                    }
                    File::Xml(xml) => {
                        cs_trace!("[*] Hunting through document {} - {:?}", document_id, xml);
                        (FileKind::Xml, xml.into())
                    }
                    File::Esedb(esedb) => {
                        cs_trace!("[*] Hunting through document {} - {:?}", document_id, esedb);
                        (FileKind::Esedb, esedb.into())
                    }
                };
                let mut hits = smallvec::smallvec![];
                for hunt in &self.inner.hunts {
                    if hunt.file != kind {
                        continue;
                    }

                    let wrapper;
                    let mapped = match &kind {
                        FileKind::Evtx => {
                            wrapper = crate::evtx::Wrapper(&value);
                            hunt.mapper.mapped(&wrapper)
                        }
                        _ => hunt.mapper.mapped(&value),
                    };
                    let mapped = if self.inner.preprocess {
                        let mut flat = Vec::with_capacity(self.inner.fields.len());
                        for field in &self.inner.fields {
                            flat.push(mapped.find(field));
                        }
                        Cache {
                            cache: Some(flat),
                            mapped: &mapped,
                        }
                    } else {
                        Cache {
                            cache: None,
                            mapped: &mapped,
                        }
                    };

                    let timestamp = match mapped.find(&hunt.timestamp) {
                        Some(value) => match value.as_str() {
                            Some(timestamp) => {
                                match NaiveDateTime::parse_from_str(
                                    timestamp,
                                    "%Y-%m-%dT%H:%M:%S%.6fZ",
                                ) {
                                    Ok(t) => t,
                                    Err(e) => {
                                        if self.inner.skip_errors {
                                            cs_eyellowln!(
                                                "failed to parse timestamp '{}' - {}",
                                                timestamp,
                                                e
                                            );
                                            return None;
                                        } else {
                                            return Some(Err(anyhow!(
                                                "failed to parse timestamp '{}' - {}",
                                                timestamp,
                                                e
                                            )));
                                        }
                                    }
                                }
                            }
                            None => continue,
                        },
                        None => continue,
                    };

                    if self.skip(timestamp).ok()? {
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
                                let rules = self.inner.rules.iter().collect::<Vec<(_, _)>>();
                                let matches = rules
                                    .iter()
                                    .filter_map(|(rid, rule)| {
                                        if !rule.is_kind(kind) {
                                            return None;
                                        }
                                        if exclusions.contains(rid) {
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
                                        let mut files = files.lock().expect("could not lock files");
                                        files.insert(document_id, (value.clone(), timestamp));
                                        let mut hasher = FxHasher::default();
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
                                        let mut aggregates =
                                            aggregates.lock().expect("could not lock aggregates");
                                        let aggregates = aggregates
                                            .entry((hunt.id, *rid))
                                            .or_insert((aggregate, FxHashMap::default()));
                                        let docs = aggregates.1.entry(id).or_default();
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
                                Filter::Detection(detection) => {
                                    tau_engine::solve(detection, &mapped)
                                }
                                Filter::Expression(expression) => {
                                    tau_engine::core::solve(expression, &mapped)
                                }
                            };
                            if hit {
                                if let Some(aggregate) = aggregate {
                                    let mut files = files.lock().expect("could not lock files");
                                    files.insert(document_id, (value.clone(), timestamp));
                                    let mut hasher = FxHasher::default();
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
                                    let mut aggregates =
                                        aggregates.lock().expect("could not lock aggregates");
                                    let aggregates = aggregates
                                        .entry((hunt.id, hunt.id))
                                        .or_insert((aggregate, FxHashMap::default()));
                                    let docs = aggregates.1.entry(id).or_default();
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
                cs_trace!("[*] Hunted through document {}", document_id);
                if !hits.is_empty() {
                    if let Some(mut cache) = cache.as_ref() {
                        let mut offset = offset.lock().expect("could not lock offset");
                        let json = serde_json::to_string(&Json::from(value))
                            .expect("could not serialise data");
                        let _ = cache.write_all(json.as_bytes());
                        let val = *offset;
                        let size = json.as_bytes().len();
                        *offset += size;
                        Some(Ok(Detections {
                            hits,
                            kind: Kind::Cached {
                                document: RawDocument {
                                    kind,
                                    path: file,
                                    data: None,
                                },
                                offset: val,
                                size,
                            },
                        }))
                    } else {
                        Some(Ok(Detections {
                            hits,
                            kind: Kind::Individual {
                                document: Document {
                                    kind,
                                    path: file,
                                    data: bincode::serialize(&value).ok()?,
                                },
                            },
                        }))
                    }
                } else {
                    None
                }
            })
            .collect::<crate::Result<Vec<Detections>>>()?;
        let aggregates = aggregates.into_inner().expect("could not lock aggregates");
        let files = files.into_inner().expect("could not lock aggregates");
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
                        let (value, timestamp) = files.get(id).expect("could not get document");
                        documents.push(Document {
                            kind: kind.clone(),
                            path: file,
                            data: bincode::serialize(&value)?,
                        });
                        timestamps.push(*timestamp);
                    }
                    timestamps.sort();
                    detections.push(Detections {
                        hits: smallvec::smallvec![Hit {
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
            let localised = Utc.from_utc_datetime(&timestamp);
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
