use std::collections::HashSet;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

use anyhow::Result;
use regex::Regex;
use serde::Deserialize;
use serde_yaml::{Mapping, Sequence, Value as Yaml};

#[derive(Clone, Deserialize)]
struct Detection {
    #[serde(default)]
    pub condition: Option<Yaml>,
    #[serde(flatten)]
    pub identifiers: Mapping,
}

#[derive(Clone, Deserialize)]
struct LogSource {
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub product: Option<String>,
    #[serde(default)]
    pub service: Option<String>,
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
    pub references: Option<Vec<String>>,
    #[serde(default)]
    pub status: Option<String>,
}

#[derive(Clone, Deserialize)]
struct Sigma {
    #[serde(default, flatten)]
    pub header: Option<Header>,
    #[serde(default)]
    pub level: Option<String>,
    #[serde(default)]
    pub logsource: Option<LogSource>,

    #[serde(default)]
    pub detection: Option<Detection>,
}

impl Sigma {
    pub fn as_base(&self) -> Option<Mapping> {
        let mut tau = Mapping::new();
        let header = self.header.clone()?;
        tau.insert("title".into(), header.title.into());
        tau.insert("description".into(), header.description.into());
        if let Some(status) = header.status {
            tau.insert("status".into(), status.into());
        } else {
            tau.insert("status".into(), "testing".into());
        }
        if let Some(references) = header.references {
            tau.insert("references".into(), references.into());
        }
        if let Some(author) = header.author {
            tau.insert(
                "authors".into(),
                author.split(", ").collect::<Vec<_>>().into(),
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
        self.contains('|') | self.contains('*') | self.contains(" of ")
    }
}

trait Match {
    fn as_contains(&self) -> String;
    fn as_endswith(&self) -> String;
    fn as_match(&self) -> Option<String>;
    fn as_regex(&self) -> Option<String>;
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
    fn as_regex(&self) -> Option<String> {
        let _ = Regex::new(self).ok()?;
        Some(format!("?{}", self))
    }
    fn as_startswith(&self) -> String {
        format!("i{}*", self)
    }
}

fn parse_identifier(value: &Yaml, modifiers: &HashSet<String>) -> Result<Yaml> {
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
                scratch.push(parse_identifier(s, modifiers)?);
            }
            Yaml::Sequence(scratch)
        }
        Yaml::String(s) => {
            if modifiers.contains("contains") {
                Yaml::String(s.as_contains())
            } else if modifiers.contains("endswith") {
                Yaml::String(s.as_endswith())
            } else if modifiers.contains("re") {
                let r = match s.as_regex() {
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
                        return Err(anyhow!(s.to_owned()).context("unsupported match"));
                    }
                };
                Yaml::String(s)
            }
        }
        _ => value.clone(),
    };
    Ok(v)
}

fn prepare(detection: Detection, extra: Option<Detection>) -> Result<Detection> {
    let mut detection = detection;
    let condition = detection
        .condition
        .clone()
        .or(extra.as_ref().and_then(|e| e.condition.clone()));
    if let Some(c) = &condition {
        if c == "all of them" {
            let mut scratch = Sequence::new();
            for (_, v) in &detection.identifiers {
                scratch.push(v.clone());
            }
            if let Some(d) = extra {
                for (_, v) in d.identifiers {
                    scratch.push(v);
                }
            }
            let mut identifiers = Mapping::new();
            identifiers.insert("A".into(), scratch.into());
            detection = Detection {
                condition: Some("all(A)".into()),
                identifiers,
            }
        } else if c == "1 of them" {
            let mut scratch = Sequence::new();
            for (_, v) in &detection.identifiers {
                scratch.push(v.clone());
            }
            if let Some(d) = extra {
                for (_, v) in d.identifiers {
                    scratch.push(v);
                }
            }
            let mut identifiers = Mapping::new();
            identifiers.insert("A".into(), scratch.into());
            detection = Detection {
                condition: Some("of(A, 1)".into()),
                identifiers,
            }
        } else if let Some(d) = extra {
            let mut identifiers = detection.identifiers;
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
            detection = Detection {
                condition,
                identifiers,
            }
        }
    }
    Ok(detection)
}

fn detections_to_tau(detection: Detection) -> Result<Mapping> {
    let mut tau = Mapping::new();
    let mut det = Mapping::new();

    // Handle condition statement
    let condition = match detection.condition {
        Some(conditions) => match conditions {
            Yaml::Sequence(s) => {
                let mut parts = vec![];
                for s in s {
                    let s = match s.as_str() {
                        Some(s) => s.to_string(),
                        None => {
                            return Err(anyhow!("{:?}", s).context("unsupported condition"));
                        }
                    };
                    if s.unsupported() {
                        return Err(anyhow!("{:?}", s).context("unsupported condition"));
                    }
                    parts.push(format!("({})", s));
                }
                parts.join(" or ")
            }
            Yaml::String(s) => {
                if s.unsupported() {
                    return Err(anyhow!(s).context("unsupported condition"));
                }
                s
            }
            u => {
                return Err(anyhow!("{:?}", u).context("unsupported condition"));
            }
        },
        None => bail!("missing condition"),
    };
    det.insert(
        "condition".into(),
        condition
            .replace(" AND ", " and ")
            .replace(" NOT ", " not ")
            .replace(" OR ", " or ")
            .into(),
    );

    // Handle identifiers
    for (k, v) in detection.identifiers {
        let k = match k.as_str() {
            Some(s) => s.to_string(),
            None => bail!("identifiers must be strings"),
        };
        if k == "timeframe" {
            bail!("timeframe based rules cannot be converted");
        }
        let mut multi = false;
        let blocks = match v {
            Yaml::Sequence(s) => {
                multi = true;
                s
            }
            Yaml::Mapping(m) => vec![Yaml::Mapping(m)],
            _ => {
                bail!("identifier blocks must be a mapping or a sequence of mappings");
            }
        };
        let mut maps = vec![];
        for v in blocks {
            let mapping = match v.as_mapping() {
                Some(m) => m,
                None => bail!("keyless identifiers cannot be converted"),
            };
            let mut fields = Mapping::new();
            for (f, v) in mapping {
                let f = match f.as_str() {
                    Some(s) => s.to_string(),
                    None => bail!("[!] keys must strings"),
                };
                let mut it = f.split('|');
                let mut f = it.next().expect("could not get field").to_string();
                let modifiers: HashSet<String> = it.map(|s| s.to_string()).collect();
                if modifiers.contains("all") {
                    f = format!("all({})", f);
                }
                let v = parse_identifier(v, &modifiers)?;
                fields.insert(f.into(), v);
            }
            maps.push(fields.into());
        }
        if multi {
            det.insert(k.into(), Yaml::Sequence(maps));
        } else {
            det.insert(k.into(), maps.remove(0));
        }
    }
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
    if main.header.and_then(|m| m.action).is_some() {
        for sigma in sigma.into_iter() {
            if let Some(extension) = sigma.detection {
                let detection = match &main.detection {
                    Some(d) => prepare(d.clone(), Some(extension)),
                    None => prepare(extension, None),
                }?;
                let tau = detections_to_tau(detection)?;
                let mut rule = base.clone();
                if let Some(level) = main.level.as_ref() {
                    rule.insert("level".into(), level.clone().into());
                }
                for (k, v) in tau {
                    rule.insert(k, v);
                }
                rules.push(rule.into());
            }
        }
    } else {
        let mut rule = base;
        if let Some(detection) = main.detection {
            let detection = prepare(detection, None)?;
            let tau = detections_to_tau(detection)?;
            if let Some(level) = main.level {
                rule.insert("level".into(), level.into());
            }
            for (k, v) in tau {
                rule.insert(k, v);
            }
            rules.push(rule.into());
        }
    }

    Ok(rules)
}
