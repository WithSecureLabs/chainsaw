use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

use anyhow::Result;
use base64::Engine;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Sequence, Value as Yaml};
use tau_engine::{Document, Rule as Tau};

use super::{Level, Status};

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub struct Rule {
    #[serde(alias = "title")]
    pub name: String,
    #[serde(flatten)]
    pub tau: Tau,

    #[serde(default)]
    pub aggregate: Option<super::Aggregate>,

    pub authors: Vec<String>,
    pub description: String,
    pub level: Level,
    pub status: Status,

    #[serde(default)]
    pub falsepositives: Option<Vec<String>>,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub logsource: Option<LogSource>,
    #[serde(default)]
    pub references: Option<Vec<String>>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
}

impl Document for Rule {
    fn find(&self, key: &str) -> Option<tau_engine::Value> {
        use tau_engine::Value as Tau;
        // NOTE: We have not implemented all fields here...
        match key {
            "title" => Some(Tau::String(Cow::Borrowed(&self.name))),
            "level" => Some(Tau::String(Cow::Owned(self.level.to_string()))),
            "status" => Some(Tau::String(Cow::Owned(self.status.to_string()))),
            "id" => self.id.as_ref().map(|id| Tau::String(Cow::Borrowed(id))),
            "logsource.category" => self
                .logsource
                .as_ref()
                .and_then(|ls| ls.category.as_ref().map(|c| Tau::String(Cow::Borrowed(c)))),
            "logsource.definition" => self.logsource.as_ref().and_then(|ls| {
                ls.definition
                    .as_ref()
                    .map(|c| Tau::String(Cow::Borrowed(c)))
            }),
            "logsource.product" => self
                .logsource
                .as_ref()
                .and_then(|ls| ls.product.as_ref().map(|c| Tau::String(Cow::Borrowed(c)))),
            "logsource.service" => self
                .logsource
                .as_ref()
                .and_then(|ls| ls.service.as_ref().map(|c| Tau::String(Cow::Borrowed(c)))),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Aggregate {
    pub count: String,
    pub fields: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
struct Detection {
    #[serde(default)]
    pub condition: Option<Yaml>,
    #[serde(flatten)]
    pub identifiers: Mapping,
}

#[derive(Clone, Deserialize)]
struct Header {
    pub title: String,
    pub description: String,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub falsepositives: Option<Vec<String>>,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub logsource: Option<LogSource>,
    #[serde(default)]
    pub references: Option<Vec<String>>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LogSource {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub definition: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
}

#[derive(Clone, Deserialize)]
struct Sigma {
    #[serde(default)]
    pub detection: Option<Detection>,
    #[serde(default, flatten)]
    pub header: Option<Header>,
    #[serde(default)]
    pub level: Option<String>,
}

impl Sigma {
    pub fn as_base(&self) -> Option<Mapping> {
        let mut tau = Mapping::new();
        let header = self.header.clone()?;
        tau.insert("title".into(), header.title.into());
        tau.insert("description".into(), header.description.into());
        if let Some(status) = header.status {
            let status = match status.as_str() {
                "stable" => status.to_owned(),
                _ => "experimental".to_owned(),
            };
            tau.insert("status".into(), status.into());
        } else {
            tau.insert("status".into(), "experimental".into());
        }
        if let Some(falsepositives) = header.falsepositives {
            tau.insert("falsepositives".into(), falsepositives.into());
        }
        if let Some(id) = header.id {
            tau.insert("id".into(), id.into());
        }
        if let Some(logsource) = header.logsource {
            tau.insert(
                "logsource".into(),
                serde_yaml::to_value(logsource).expect("could not serialise logsource"),
            );
        }
        if let Some(references) = header.references {
            tau.insert("references".into(), references.into());
        }
        if let Some(tags) = header.tags {
            tau.insert("tags".into(), tags.into());
        }
        if let Some(author) = header.author {
            tau.insert(
                "authors".into(),
                author
                    .split(',')
                    .map(|a| a.trim())
                    .collect::<Vec<_>>()
                    .into(),
            );
        } else {
            tau.insert("authors".into(), vec!["unknown"].into());
        }
        Some(tau)
    }
}

trait Condition {
    fn unsupported(&self) -> bool;
}

impl Condition for String {
    fn unsupported(&self) -> bool {
        self.contains(" | ")
            | self.contains('*')
            | self.contains(" avg ")
            | self.contains(" of ")
            | self.contains(" max ")
            | self.contains(" min ")
            | self.contains(" near ")
            | self.contains(" sum ")
    }
}

trait Match {
    fn as_contains(&self) -> String;
    fn as_endswith(&self) -> String;
    fn as_match(&self) -> Option<String>;
    fn as_regex(&self, convert: bool) -> Option<String>;
    fn as_startswith(&self) -> String;
}

impl Match for String {
    fn as_contains(&self) -> String {
        format!("i*{}*", self)
    }
    fn as_endswith(&self) -> String {
        format!("i*{}", self)
    }
    fn as_match(&self) -> Option<String> {
        // TODO: Handle nested wildcards
        let len = self.len();
        if len > 1 {
            let mut start = 0;
            let mut end = len;
            if self.starts_with('*') {
                start += 1;
            }
            if self.ends_with('*') {
                end -= 1;
            }
            if self[start..end].contains('*') || self[start..end].contains('?') {
                return None;
            }
        }
        Some(format!("i{}", self))
    }
    fn as_regex(&self, convert: bool) -> Option<String> {
        if convert {
            let literal = regex::escape(self);
            let mut scratch = Vec::with_capacity(literal.len());
            let mut escaped = false;
            for c in literal.chars() {
                match c {
                    '*' | '?' => {
                        if !escaped {
                            scratch.push('.');
                        }
                    }
                    '\\' => {
                        escaped = !escaped;
                    }
                    _ => {
                        escaped = false;
                    }
                }
                scratch.push(c);
            }
            Some(format!("?{}", scratch.into_iter().collect::<String>()))
        } else {
            let _ = Regex::new(self).ok()?;
            Some(format!("?{}", self))
        }
    }
    fn as_startswith(&self) -> String {
        format!("i{}*", self)
    }
}

// NOTE: We list the supported ones, so if any new ones appear we don't silently error.
lazy_static::lazy_static! {
    static ref SUPPORTED_MODIFIERS: HashSet<String> = {
        let mut set = HashSet::new();
        set.insert("all".to_owned());
        set.insert("base64".to_owned());
        set.insert("base64offset".to_owned());
        set.insert("contains".to_owned());
        set.insert("endswith".to_owned());
        set.insert("startswith".to_owned());
        set.insert("re".to_owned());
        set
    };
}

fn parse_identifier(value: &Yaml, modifiers: &HashSet<String>) -> Result<Yaml> {
    let mut unsupported: Vec<String> = modifiers
        .difference(&*SUPPORTED_MODIFIERS)
        .cloned()
        .collect();
    if !unsupported.is_empty() {
        unsupported.sort();
        return Err(anyhow!(unsupported.join(", ")).context("unsupported modifiers"));
    }

    let v = match value {
        Yaml::Mapping(m) => {
            let mut scratch = Mapping::new();
            for (k, v) in m {
                scratch.insert(k.clone(), parse_identifier(v, modifiers)?);
            }
            Yaml::Mapping(scratch)
        }
        Yaml::Sequence(s) => {
            let mut scratch = vec![];
            for s in s {
                let value = parse_identifier(s, modifiers)?;
                match value {
                    Yaml::Sequence(s) => scratch.extend(s),
                    _ => scratch.push(value),
                }
            }
            Yaml::Sequence(scratch)
        }
        Yaml::String(s) => {
            if modifiers.contains("base64") {
                let mut remaining = modifiers.clone();
                let _ = remaining.remove("base64");
                let encoded = base64::engine::general_purpose::STANDARD.encode(s);
                parse_identifier(&Yaml::String(encoded), &remaining)?
            } else if modifiers.contains("base64offset") {
                let mut remaining = modifiers.clone();
                let _ = remaining.remove("base64offset");
                let mut scratch = Vec::with_capacity(3);
                for i in 0..3 {
                    let mut value = (0..i).fold("".to_owned(), |mut s, _| {
                        s.push(' ');
                        s
                    });
                    value.push_str(s);
                    let encoded = base64::engine::general_purpose::STANDARD.encode(&value);
                    static S: [usize; 3] = [0, 2, 3];
                    static E: [usize; 3] = [0, 3, 2];
                    let len = value.len();
                    let trimmed = encoded[S[i]..encoded.len() - E[len % 3]].to_owned();
                    scratch.push(parse_identifier(&Yaml::String(trimmed), &remaining)?);
                }
                Yaml::Sequence(scratch)
            } else if modifiers.contains("contains") {
                Yaml::String(s.as_contains())
            } else if modifiers.contains("endswith") {
                Yaml::String(s.as_endswith())
            } else if modifiers.contains("re") {
                let r = match s.as_regex(false) {
                    Some(r) => r,
                    None => {
                        return Err(anyhow!(s.to_owned()).context("unsupported regex"));
                    }
                };
                Yaml::String(r)
            } else if modifiers.contains("startswith") {
                Yaml::String(s.as_startswith())
            } else {
                let s = match s.as_match() {
                    Some(s) => s,
                    None => {
                        if let Some(r) = s.as_regex(true) {
                            r
                        } else {
                            return Err(anyhow!(s.to_owned()).context("unsupported match"));
                        }
                    }
                };
                Yaml::String(s)
            }
        }
        _ => value.clone(),
    };
    Ok(v)
}

fn prepare_condition(condition: &str) -> Result<(String, Option<Aggregate>)> {
    if condition.contains(" | ") {
        let (condition, agg) = condition
            .split_once(" | ")
            .expect("could not split condition");
        let mut parts = agg.split_whitespace();
        let mut fields = vec![];
        // NOTE: We only support count atm...
        // agg-function(agg-field) [ by group-field ] comparison-op value
        if let Some(kind) = parts.next() {
            if let Some(rest) = kind.strip_prefix("count(") {
                if let Some(field) = rest.strip_suffix(')') {
                    if !field.is_empty() {
                        fields.push(field.to_owned());
                    }
                } else {
                    anyhow::bail!("invalid agg function");
                }
            } else {
                anyhow::bail!("unsupported agg function - {}", kind);
            }
        } else {
            anyhow::bail!("missing agg function");
        }
        let mut part = match parts.next() {
            Some(part) => part,
            None => anyhow::bail!("invalid aggregation"),
        };
        if part == "by" {
            let field = match parts.next() {
                Some(field) => field,
                None => anyhow::bail!("missing group field"),
            };
            fields.push(field.to_owned());
            part = match parts.next() {
                Some(part) => part,
                None => anyhow::bail!("invalid aggregation"),
            };
        }
        let number = match parts.next() {
            Some(part) => part,
            None => anyhow::bail!("invalid aggregation"),
        };
        Ok((
            condition.to_owned(),
            Some(Aggregate {
                count: format!("{}{}", part, number),
                fields,
            }),
        ))
    } else {
        Ok((condition.to_owned(), None))
    }
}

fn prepare(
    detection: Detection,
    extra: Option<Detection>,
) -> Result<(Detection, Option<Aggregate>)> {
    let mut aggregate = None;
    let mut detection = detection;
    let condition = extra
        .as_ref()
        .and_then(|e| e.condition.clone())
        .or_else(|| detection.condition.clone());
    if let Some(c) = &condition {
        let mut conditions = vec![];
        match c {
            Yaml::String(c) => conditions.push(c),
            Yaml::Sequence(s) => {
                if s.len() == 1 {
                    let x = s.iter().next().expect("could not get condition");
                    if let Yaml::String(c) = x {
                        conditions.push(c)
                    } else {
                        anyhow::bail!("condition must be a string");
                    }
                } else {
                    anyhow::bail!("condition must be a string");
                }
            }
            _ => anyhow::bail!("condition must be a string"),
        };
        let condition = if conditions.len() == 1 {
            let (c, a) = conditions
                .into_iter()
                .map(|c| prepare_condition(c))
                .next()
                .expect("could not get condition")?;
            aggregate = a;
            c
        } else {
            let mut scratch = Vec::with_capacity(conditions.len());
            for condition in conditions {
                let (c, a) = prepare_condition(condition)?;
                if a.is_some() {
                    anyhow::bail!("multiple aggregation expressions are not supported");
                }
                scratch.push(format!("({})", c));
            }
            scratch.join(" or ")
        };

        let mut identifiers = detection.identifiers;
        if let Some(d) = extra {
            for (k, v) in d.identifiers {
                match identifiers.remove(&k) {
                    Some(i) => match (i, v) {
                        (Yaml::Mapping(mut m), Yaml::Mapping(v)) => {
                            for (x, y) in v {
                                m.insert(x, y);
                            }
                            identifiers.insert(k, Yaml::Mapping(m));
                        }
                        (Yaml::Sequence(s), Yaml::Mapping(v)) => {
                            let mut z = vec![];
                            for mut ss in s.into_iter() {
                                if let Some(m) = ss.as_mapping_mut() {
                                    for (x, y) in v.clone() {
                                        m.insert(x, y);
                                    }
                                }
                                z.push(ss);
                            }
                            identifiers.insert(k, Yaml::Sequence(z));
                        }
                        (_, _) => anyhow::bail!("unsupported rule collection format"),
                    },
                    None => {
                        identifiers.insert(k, v);
                    }
                }
            }
        }
        detection = Detection {
            condition: Some(Yaml::String(condition)),
            identifiers,
        }
    }
    Ok((detection, aggregate))
}

fn detections_to_tau(detection: Detection) -> Result<Mapping> {
    let mut tau = Mapping::new();
    let mut det = Mapping::new();

    // Handle condition statement
    let condition = match detection.condition {
        Some(conditions) => match conditions {
            Yaml::String(s) => s,
            u => {
                return Err(anyhow!("{:?}", u).context("unsupported condition"));
            }
        },
        None => bail!("missing condition"),
    };

    // Handle identifiers
    // NOTE: We can be inefficient here because the tree shaker will do the hard work for us!
    let mut patches = HashMap::new();
    for (k, v) in detection.identifiers {
        let k = match k.as_str() {
            Some(s) => s.to_string(),
            None => bail!("identifiers must be strings"),
        };
        if k == "timeframe" {
            // TODO: Ignore for now as this would make the aggregator more complex...
            continue;
            //bail!("timeframe based rules cannot be converted");
        }
        match v {
            Yaml::Sequence(sequence) => {
                let mut blocks = vec![];
                for (index, entry) in sequence.into_iter().enumerate() {
                    let mapping = match entry.as_mapping() {
                        Some(mapping) => mapping,
                        None => bail!("keyless identifiers cannot be converted"),
                    };
                    let mut collect = true;
                    let mut seen = HashSet::new();
                    let mut maps = vec![];
                    for (f, v) in mapping {
                        let f = match f.as_str() {
                            Some(s) => s.to_string(),
                            None => bail!("[!] keys must strings"),
                        };
                        let mut it = f.split('|');
                        let mut f = it.next().expect("could not get field").to_string();
                        if f.is_empty() {
                            bail!("keyless identifiers cannot be converted");
                        }
                        if seen.contains(&f) {
                            collect = false;
                        }
                        seen.insert(f.clone());
                        let modifiers: HashSet<String> = it.map(|s| s.to_string()).collect();
                        if modifiers.contains("all") {
                            f = format!("all({})", f);
                        }
                        let v = parse_identifier(v, &modifiers)?;
                        let f = f.into();
                        let mut map = Mapping::new();
                        map.insert(f, v);
                        maps.push(map);
                    }
                    if collect {
                        let mut m = Mapping::new();
                        for map in maps {
                            for (k, v) in map {
                                m.insert(k, v);
                            }
                        }
                        let ident = format!("{}_{}", k, index);
                        blocks.push((ident, m.into()));
                    } else {
                        let ident = format!("all({}_{})", k, index);
                        blocks.push((
                            ident,
                            Yaml::Sequence(maps.into_iter().map(|m| m.into()).collect()),
                        ));
                    }
                }
                patches.insert(
                    k,
                    format!(
                        "({})",
                        blocks
                            .iter()
                            .map(|(k, _)| k)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(" or "),
                    ),
                );
                for (k, v) in blocks {
                    det.insert(k.into(), v);
                }
            }
            Yaml::Mapping(mapping) => {
                let mut collect = true;
                let mut seen = HashSet::new();
                let mut maps = vec![];
                for (f, v) in mapping {
                    let f = match f.as_str() {
                        Some(s) => s.to_string(),
                        None => bail!("[!] keys must strings"),
                    };
                    let mut it = f.split('|');
                    let mut f = it.next().expect("could not get field").to_string();
                    if f.is_empty() {
                        bail!("keyless identifiers cannot be converted");
                    }
                    if seen.contains(&f) {
                        collect = false;
                    }
                    seen.insert(f.clone());
                    let modifiers: HashSet<String> = it.map(|s| s.to_string()).collect();
                    if modifiers.contains("all") {
                        f = format!("all({})", f);
                    }
                    let v = parse_identifier(&v, &modifiers)?;
                    let f = f.into();
                    let mut map = Mapping::new();
                    map.insert(f, v);
                    maps.push(map);
                }
                if collect {
                    let mut m = Mapping::new();
                    for map in maps {
                        for (k, v) in map {
                            m.insert(k, v);
                        }
                    }
                    det.insert(k.into(), m.into());
                } else {
                    let ident = format!("all({})", k);
                    det.insert(
                        Yaml::String(k.clone()),
                        Yaml::Sequence(maps.into_iter().map(|m| m.into()).collect()),
                    );
                    patches.insert(k, ident);
                }
            }
            _ => {
                bail!("identifier blocks must be a mapping or a sequence of mappings");
            }
        }
    }

    let condition = condition
        .replace(" AND ", " and ")
        .replace(" NOT ", " not ")
        .replace(" OR ", " or ")
        .split_whitespace()
        .map(|ident| {
            let key = ident.trim_start_matches('(').trim_end_matches(')');
            match patches.get(key) {
                Some(v) => ident.replace(key, v),
                None => ident.to_owned(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ");

    let condition = if condition == "all of them" {
        let mut identifiers = vec![];
        for (k, _) in &det {
            let key = k.as_str().expect("could not get key");
            match patches.get(key) {
                Some(i) => identifiers.push(i.to_owned()),
                None => identifiers.push(key.to_owned()),
            }
        }
        identifiers.join(" and ")
    } else if condition == "1 of them" {
        let mut identifiers = vec![];
        for (k, _) in &det {
            let key = k.as_str().expect("could not get key");
            match patches.get(key) {
                Some(i) => identifiers.push(i.to_owned()),
                None => identifiers.push(key.to_owned()),
            }
        }
        identifiers.join(" or ")
    } else {
        let mut mutated = vec![];
        let mut parts = condition.split_whitespace();
        while let Some(part) = parts.next() {
            let mut token = part;
            while let Some(tail) = token.strip_prefix('(') {
                mutated.push("(".to_owned());
                token = tail;
            }
            match token {
                "all" | "1" => {
                    if let Some(next) = parts.next() {
                        if next != "of" {
                            mutated.push(token.to_owned());
                            mutated.push(next.to_owned());
                            continue;
                        }

                        if let Some(next) = parts.next() {
                            let mut brackets = vec![];
                            let mut identifier = next;
                            while let Some(head) = identifier.strip_suffix(')') {
                                brackets.push(")".to_owned());
                                identifier = head;
                            }
                            if let Some(ident) = identifier.strip_suffix('*') {
                                let mut keys = vec![];
                                for (k, _) in &det {
                                    if let Yaml::String(key) = k {
                                        if key.starts_with(ident) {
                                            match patches.get(key) {
                                                Some(i) => keys.push(i.to_owned()),
                                                None => keys.push(key.to_owned()),
                                            }
                                        }
                                    }
                                }
                                if keys.is_empty() {
                                    anyhow::bail!("could not find any applicable identifiers");
                                }
                                let expression = if token == "all" {
                                    format!("({})", keys.join(" and "))
                                } else if token == "1" {
                                    format!("({})", keys.join(" or "))
                                } else {
                                    unreachable!();
                                };
                                mutated.push(expression);
                            } else {
                                let key = match patches.get(identifier) {
                                    Some(i) => i,
                                    None => identifier,
                                };
                                let key = next.replace(identifier, key);
                                if part == "all" {
                                    mutated.push(format!("all({})", key));
                                } else if part == "1" {
                                    mutated.push(format!("of({}, 1)", key));
                                }
                            }
                            mutated.extend(brackets);
                            continue;
                        }
                    }
                }
                _ => {}
            }
            mutated.push(token.to_owned());
        }
        mutated.join(" ").replace("( ", "(").replace(" )", ")")
    };
    if condition.unsupported() {
        return Err(anyhow!(condition).context("unsupported condition"));
    }

    det.insert("condition".into(), condition.into());

    tau.insert("detection".into(), det.into());
    tau.insert("true_positives".into(), Sequence::new().into());
    tau.insert("true_negatives".into(), Sequence::new().into());

    Ok(tau)
}

pub fn load(rule: &Path) -> Result<Vec<Yaml>> {
    let regex = Regex::new(r"---\s*\n").expect("invalid regex");
    let mut file = File::open(rule)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let mut sigma: Vec<Sigma> = regex
        .split(&contents)
        .filter_map(|p| {
            if !p.is_empty() {
                serde_yaml::from_str::<Sigma>(p).ok()
            } else {
                None
            }
        })
        .collect();

    // Silently error if we found no sigma rules.
    if sigma.is_empty() {
        return Ok(vec![]);
    }

    let main = sigma.remove(0);
    let base = match main.as_base() {
        Some(base) => base,
        None => bail!("failed to parse sigma rule"),
    };

    let mut rules = vec![];

    // Sigma has this annoying feature called Rule Collections which makes parsing a PITA at the
    // cost of slightly better maintainability. I am not a fan but we have to handle it as best as
    // possible.
    // https://github.com/SigmaHQ/sigma/wiki/Specification#rule-collections
    // TODO: This is a minimal implementation which supports most of the styles found in the
    // Windows rules. We can do a more complete one when required.
    let mut single = false;
    if main.header.and_then(|m| m.action).is_some() {
        for sigma in sigma.into_iter() {
            if let Some(extension) = sigma.detection {
                let (detection, agg) = match &main.detection {
                    Some(d) => prepare(d.clone(), Some(extension)),
                    None => prepare(extension, None),
                }?;
                let tau = detections_to_tau(detection)?;
                let mut rule = base.clone();
                if let Some(level) = &main.level {
                    let level = match level.as_str() {
                        "critical" | "high" | "medium" | "low" => level.to_owned(),
                        _ => "info".to_owned(),
                    };
                    rule.insert("level".into(), level.into());
                } else {
                    rule.insert("level".into(), "info".into());
                }
                for (k, v) in tau {
                    rule.insert(k, v);
                }
                if let Some(agg) = agg.and_then(|a| serde_yaml::to_value(a).ok()) {
                    rule.insert(Yaml::String("aggregate".to_owned()), agg);
                }
                rules.push(rule.into());
            } else {
                single = true;
            }
        }
    } else {
        single = true;
    }

    if single {
        let mut rule = base;
        if let Some(detection) = main.detection {
            let (detection, agg) = prepare(detection, None)?;
            let tau = detections_to_tau(detection)?;
            if let Some(level) = &main.level {
                let level = match level.as_str() {
                    "critical" | "high" | "medium" | "low" => level.to_owned(),
                    _ => "info".to_owned(),
                };
                rule.insert("level".into(), level.into());
            } else {
                rule.insert("level".into(), "info".into());
            }
            for (k, v) in tau {
                rule.insert(k, v);
            }
            if let Some(agg) = agg.and_then(|a| serde_yaml::to_value(a).ok()) {
                rule.insert(Yaml::String("aggregate".to_owned()), agg);
            }
            rules.push(rule.into());
        }
    }

    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unsupported_conditions() {
        let condition = "search_expression | aggregation_expression".to_owned();
        assert_eq!(condition.unsupported(), true);

        let condition = "selection*".to_owned();
        assert_eq!(condition.unsupported(), true);

        let condition = "1 of them".to_owned();
        assert_eq!(condition.unsupported(), true);
    }

    #[test]
    fn test_match_contains() {
        let x = "foobar".to_owned();
        assert_eq!(x.as_contains(), "i*foobar*");
    }

    #[test]
    fn test_match_endswith() {
        let x = "foobar".to_owned();
        assert_eq!(x.as_endswith(), "i*foobar");
    }

    #[test]
    fn test_match() {
        let x = "foobar".to_owned();
        assert_eq!(x.as_match().unwrap(), "ifoobar");

        let x = "*foobar".to_owned();
        assert_eq!(x.as_match().unwrap(), "i*foobar");

        let x = "foobar*".to_owned();
        assert_eq!(x.as_match().unwrap(), "ifoobar*");

        let x = "*foobar*".to_owned();
        assert_eq!(x.as_match().unwrap(), "i*foobar*");

        // NOTE: These are none as we need to write regex to support them...
        let x = "foo*bar".to_owned();
        assert_eq!(x.as_match().is_none(), true);
        let x = "foo?bar".to_owned();
        assert_eq!(x.as_match().is_none(), true);
    }

    #[test]
    fn test_match_regex() {
        let x = "foobar".to_owned();
        assert_eq!(x.as_regex(false).unwrap(), "?foobar");
    }

    #[test]
    fn test_match_startswith() {
        let x = "foobar".to_owned();
        assert_eq!(x.as_startswith(), "ifoobar*");
    }

    #[test]
    fn test_parse_identifier() {
        let rule = r#"
            array:
            - ia
            - ib
            - ic
            mapping:
                k1: iv1
                k2: iv2
            number: 30
            string: iabcd
        "#;
        let expected: serde_yaml::Value = serde_yaml::from_str(&rule).unwrap();

        let rule = r#"
            array:
            - a
            - b
            - c
            mapping:
                k1: v1
                k2: v2
            number: 30
            string: abcd
        "#;
        let yaml: serde_yaml::Value = serde_yaml::from_str(&rule).unwrap();
        let yaml = parse_identifier(&yaml, &HashSet::new()).unwrap();
        assert_eq!(yaml, expected);
    }

    #[test]
    fn test_prepare() {
        let expected = r#"
            A:
                string: abcd
            condition: A
        "#;
        let expected: Detection = serde_yaml::from_str(&expected).unwrap();

        let detection = r#"
            A:
                string: abcd
            condition: A
        "#;

        let detection: Detection = serde_yaml::from_str(&detection).unwrap();
        let (detection, _) = prepare(detection, None).unwrap();
        assert_eq!(detection, expected);
    }

    #[test]
    fn test_prepare_group() {
        let expected = r#"
            A:
                string: abcd
            B:
                string: efgh
            condition: A and B
        "#;
        let expected: Detection = serde_yaml::from_str(&expected).unwrap();

        let base = r#"
            A:
                string: abcd
            condition: A
        "#;
        let detection = r#"
            B:
                string: efgh
            condition: A and B
        "#;

        let base: Detection = serde_yaml::from_str(&base).unwrap();
        let detection: Detection = serde_yaml::from_str(&detection).unwrap();
        let (detection, _) = prepare(base, Some(detection)).unwrap();
        assert_eq!(detection, expected);
    }

    #[test]
    fn test_detection_to_tau_0() {
        let expected = r#"
            detection:
                A:
                    array:
                    - ia
                    - ib
                    - ic
                    mapping:
                        k1: iv1
                        k2: iv2
                    number: 30
                    string: iabcd
                B:
                    - string: i*foobar*
                    - string: i*foobar
                    - string: ?foobar
                    - string: ifoobar*
                C_0:
                    string: i*foobar*
                C_1:
                    string: i*foobar
                C_2:
                    string: ?foobar
                C_3:
                    string: ifoobar*
                condition: A and all(B) and (C_0 or C_1 or C_2 or C_3)
            true_negatives: []
            true_positives: []
        "#;
        let expected: serde_yaml::Value = serde_yaml::from_str(&expected).unwrap();

        let detection = r#"
            A:
                array:
                - a
                - b
                - c
                mapping:
                    k1: v1
                    k2: v2
                number: 30
                string: abcd
            B:
                string|contains: foobar
                string|endswith: foobar
                string|re: foobar
                string|startswith: foobar
            C:
                - string|contains: foobar
                - string|endswith: foobar
                - string|re: foobar
                - string|startswith: foobar
            condition: A and B and C
        "#;
        let detection: Detection = serde_yaml::from_str(&detection).unwrap();
        let detection = detections_to_tau(detection).unwrap();
        assert_eq!(detection, *expected.as_mapping().unwrap());
    }

    #[test]
    fn test_detection_to_tau_all_of_them() {
        let expected = r#"
            detection:
                A:
                    string: iabcd
                B:
                    string: iefgh
                condition: A and B
            true_negatives: []
            true_positives: []
        "#;
        let expected: serde_yaml::Value = serde_yaml::from_str(&expected).unwrap();

        let detection = r#"
            A:
                string: abcd
            B:
                string: efgh
            condition: all of them
        "#;

        let detection: Detection = serde_yaml::from_str(&detection).unwrap();
        let detection = detections_to_tau(detection).unwrap();
        assert_eq!(detection, *expected.as_mapping().unwrap());
    }

    #[test]
    fn test_detection_to_tau_one_of_them() {
        let expected = r#"
            detection:
                A:
                    string: iabcd
                B:
                    string: iefgh
                condition: A or B
            true_negatives: []
            true_positives: []
        "#;
        let expected: serde_yaml::Value = serde_yaml::from_str(&expected).unwrap();

        let detection = r#"
            A:
                string: abcd
            B:
                string: efgh
            condition: 1 of them
        "#;

        let detection: Detection = serde_yaml::from_str(&detection).unwrap();
        let detection = detections_to_tau(detection).unwrap();
        assert_eq!(detection, *expected.as_mapping().unwrap());
    }

    #[test]
    fn test_detection_to_tau_all_of_selection() {
        let expected = r#"
            detection:
                A:
                    string: iabcd
                selection0:
                    string: iefgh
                selection1:
                    string: iijkl
                condition: A and (selection0 and selection1)
            true_negatives: []
            true_positives: []
        "#;
        let expected: serde_yaml::Value = serde_yaml::from_str(&expected).unwrap();

        let detection = r#"
            A:
                string: abcd
            selection0:
                string: efgh
            selection1:
                string: ijkl
            condition: A and all of selection*
        "#;

        let detection: Detection = serde_yaml::from_str(&detection).unwrap();
        let detection = detections_to_tau(detection).unwrap();
        assert_eq!(detection, *expected.as_mapping().unwrap());
    }

    #[test]
    fn test_detection_to_tau_one_of_selection() {
        let expected = r#"
            detection:
                A:
                    string: iabcd
                selection0:
                    string: iefgh
                selection1:
                    string: iijkl
                condition: A and (selection0 or selection1)
            true_negatives: []
            true_positives: []
        "#;
        let expected: serde_yaml::Value = serde_yaml::from_str(&expected).unwrap();

        let detection = r#"
            A:
                string: abcd
            selection0:
                string: efgh
            selection1:
                string: ijkl
            condition: A and 1 of selection*
        "#;

        let detection: Detection = serde_yaml::from_str(&detection).unwrap();
        let detection = detections_to_tau(detection).unwrap();
        assert_eq!(detection, *expected.as_mapping().unwrap());
    }
}
