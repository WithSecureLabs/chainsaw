use std::collections::HashSet;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

use anyhow::Result;
use regex::Regex;
use serde::Deserialize;
use serde_yaml::{Mapping, Sequence, Value as Yaml};
use tau_engine::Rule as Tau;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub struct Rule {
    #[serde(alias = "title")]
    pub name: String,
    #[serde(flatten)]
    pub tau: Tau,

    pub authors: Vec<String>,
    pub description: String,
    pub level: Option<String>,
    pub status: Option<String>,
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
    let condition = extra
        .as_ref()
        .and_then(|e| e.condition.clone())
        .or_else(|| detection.condition.clone());
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
        } else {
            let condition = match c {
                Yaml::String(c) => c,
                Yaml::Sequence(s) => {
                    if s.len() == 1 {
                        let x = s.iter().next().expect("could not get condition");
                        if let Yaml::String(c) = x {
                            c
                        } else {
                            anyhow::bail!("condition must be a string");
                        }
                    } else {
                        anyhow::bail!("condition must be a string");
                    }
                }
                _ => anyhow::bail!("condition must be a string"),
            };
            let mut identifiers = detection.identifiers;
            let mut index = 0;
            let mut mutated = vec![];
            let mut parts = condition.split_whitespace();
            while let Some(part) = parts.next() {
                let part = if let Some(part) = part.strip_prefix("(") {
                    mutated.push("(".to_owned());
                    part
                } else {
                    part
                };
                match part {
                    "all" | "1" => {
                        if let Some(next) = parts.next() {
                            if next != "of" {
                                mutated.push(part.to_owned());
                                mutated.push(next.to_owned());
                                continue;
                            }

                            if let Some(ident) = parts.next() {
                                let mut bracket = false;
                                let ident = if let Some(ident) = ident.strip_suffix(")") {
                                    bracket = true;
                                    ident
                                } else {
                                    ident
                                };
                                if let Some(ident) = ident.strip_suffix("*") {
                                    let mut scratch = vec![];
                                    let mut keys = vec![];
                                    for (k, _) in &identifiers {
                                        if let Yaml::String(key) = k {
                                            if key.starts_with(ident) {
                                                keys.push(k.clone());
                                            }
                                        }
                                    }
                                    for key in keys {
                                        if let Some(v) = identifiers.get(&key) {
                                            scratch.push(v.clone());
                                        }
                                    }
                                    if scratch.is_empty() {
                                        anyhow::bail!("could not find any applicable identifiers");
                                    }
                                    let key = format!("tau_{}", index);
                                    if part == "all" {
                                        mutated.push(format!("all({})", key));
                                    } else if part == "1" {
                                        mutated.push(format!("of({}, 1)", key));
                                    }
                                    identifiers.insert(Yaml::String(key), Yaml::Sequence(scratch));
                                    mutated.push(")".to_owned());
                                    index += 1;
                                    continue;
                                } else {
                                    if part == "all" {
                                        mutated.push(format!("all({})", ident));
                                    } else if part == "1" {
                                        mutated.push(format!("of({}, 1)", ident));
                                    }
                                    mutated.push(")".to_owned());
                                    continue;
                                }
                            }
                        }
                    }
                    _ => {}
                }
                mutated.push(part.to_owned());
            }
            let condition = mutated.join(" ");
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
                let f = f.into();
                match fields.remove(&f) {
                    Some(x) => {
                        let s = match (x, v) {
                            (Yaml::Sequence(mut a), Yaml::Sequence(b)) => {
                                a.extend(b);
                                Yaml::Sequence(a)
                            }
                            (Yaml::Sequence(mut s), y) => {
                                s.push(y);
                                Yaml::Sequence(s)
                            }
                            (y, Yaml::Sequence(mut s)) => {
                                s.push(y);
                                Yaml::Sequence(s)
                            }
                            (Yaml::Mapping(_), _) | (_, Yaml::Mapping(_)) => {
                                bail!("could not merge identifiers")
                            }
                            (a, b) => Yaml::Sequence(vec![a, b]),
                        };
                        fields.insert(f, s);
                    }
                    None => {
                        fields.insert(f, v);
                    }
                }
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
    let mut single = false;
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
        assert_eq!(x.as_regex().unwrap(), "?foobar");
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
        let detection = prepare(detection, None).unwrap();
        assert_eq!(detection, expected);
    }

    #[test]
    fn test_prepare_all_of_them() {
        let expected = r#"
            A:
                - string: abcd
                - string: efgh
            condition: all(A)
        "#;
        let expected: Detection = serde_yaml::from_str(&expected).unwrap();

        let detection = r#"
            A:
                string: abcd
            B:
                string: efgh
            condition: all of them
        "#;

        let detection: Detection = serde_yaml::from_str(&detection).unwrap();
        let detection = prepare(detection, None).unwrap();
        assert_eq!(detection, expected);
    }

    #[test]
    fn test_prepare_one_of_them() {
        let expected = r#"
            A:
                - string: abcd
                - string: efgh
            condition: of(A, 1)
        "#;
        let expected: Detection = serde_yaml::from_str(&expected).unwrap();

        let detection = r#"
            A:
                string: abcd
            B:
                string: efgh
            condition: 1 of them
        "#;

        let detection: Detection = serde_yaml::from_str(&detection).unwrap();
        let detection = prepare(detection, None).unwrap();
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
        let detection = prepare(base, Some(detection)).unwrap();
        assert_eq!(detection, expected);
    }

    #[test]
    fn test_detection_to_tau() {
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
                    string:
                    - i*foobar*
                    - i*foobar
                    - ?foobar
                    - ifoobar*
                condition: A and B
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
            condition: A and B
        "#;
        let detection: Detection = serde_yaml::from_str(&detection).unwrap();
        let detection = detections_to_tau(detection).unwrap();
        assert_eq!(detection, *expected.as_mapping().unwrap());
    }
}
