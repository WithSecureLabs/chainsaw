use std::collections::HashSet;
use std::fmt;
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use tau_engine::{
    core::{
        optimiser,
        parser::{Expression, Pattern},
        Detection,
    },
    Document,
};

use crate::file::Kind as FileKind;

pub use self::chainsaw::Rule as Chainsaw;
pub use self::sigma::Rule as Sigma;

pub mod chainsaw;
pub mod sigma;

#[derive(Clone, Debug)]
pub enum Rule {
    Chainsaw(Chainsaw),
    Sigma(Sigma),
}

impl Rule {
    #[inline]
    pub fn aggregate(&self) -> &Option<Aggregate> {
        match self {
            Self::Chainsaw(c) => &c.aggregate,
            Self::Sigma(s) => &s.aggregate,
        }
    }

    #[inline]
    pub fn is_kind(&self, kind: &Kind) -> bool {
        match self {
            Self::Chainsaw(_) => kind == &Kind::Chainsaw,
            Self::Sigma(_) => kind == &Kind::Sigma,
        }
    }

    #[inline]
    pub fn level(&self) -> &Level {
        match self {
            Self::Chainsaw(c) => &c.level,
            Self::Sigma(s) => &s.level,
        }
    }

    #[inline]
    pub fn types(&self) -> &FileKind {
        match self {
            Self::Chainsaw(c) => &c.kind,
            Self::Sigma(_) => &FileKind::Unknown,
        }
    }

    #[inline]
    pub fn name(&self) -> &String {
        match self {
            Self::Chainsaw(c) => &c.name,
            Self::Sigma(s) => &s.name,
        }
    }

    #[inline]
    pub fn solve(&self, document: &dyn Document) -> bool {
        match self {
            Self::Chainsaw(c) => match &c.filter {
                Filter::Detection(detection) => tau_engine::solve(detection, document),
                Filter::Expression(expression) => tau_engine::core::solve(expression, document),
            },
            Self::Sigma(s) => tau_engine::solve(&s.tau.detection, document),
        }
    }

    #[inline]
    pub fn status(&self) -> &Status {
        match self {
            Self::Chainsaw(c) => &c.status,
            Self::Sigma(s) => &s.status,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct Aggregate {
    #[serde(deserialize_with = "crate::ext::tau::deserialize_numeric")]
    pub count: Pattern,
    pub fields: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum Filter {
    Detection(Detection),
    #[serde(deserialize_with = "crate::ext::tau::deserialize_expression")]
    Expression(Expression),
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Chainsaw,
    Sigma,
}

impl Default for Kind {
    fn default() -> Self {
        Self::Chainsaw
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Chainsaw => write!(f, "chainsaw"),
            Self::Sigma => write!(f, "sigma"),
        }
    }
}

impl FromStr for Kind {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v = match s {
            "chainsaw" => Self::Chainsaw,
            "sigma" => Self::Sigma,
            _ => anyhow::bail!("unknown kind, must be: chainsaw, or sigma"),
        };
        Ok(v)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Critical => write!(f, "critical"),
            Self::High => write!(f, "high"),
            Self::Medium => write!(f, "medium"),
            Self::Low => write!(f, "low"),
            Self::Info => write!(f, "info"),
        }
    }
}

impl FromStr for Level {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v = match s {
            "critical" => Self::Critical,
            "high" => Self::High,
            "medium" => Self::Medium,
            "low" => Self::Low,
            "info" => Self::Info,
            _ => anyhow::bail!("unknown level, must be: critical, high, medium, low or info"),
        };
        Ok(v)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Stable,
    Experimental,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stable => write!(f, "stable"),
            Self::Experimental => write!(f, "experimental"),
        }
    }
}

impl FromStr for Status {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v = match s {
            "stable" => Self::Stable,
            "experimental" => Self::Experimental,
            _ => anyhow::bail!("unknown status, must be: stable or experimental"),
        };
        Ok(v)
    }
}
pub fn load(
    kind: Kind,
    path: &Path,
    kinds: &Option<HashSet<Kind>>,
    levels: &Option<HashSet<Level>>,
    statuses: &Option<HashSet<Status>>,
) -> crate::Result<Vec<Rule>> {
    if let Some(x) = path.extension() {
        if x != "yml" && x != "yaml" {
            anyhow::bail!("rule must have a yaml file extension");
        }
    }
    let mut rules = match kind {
        Kind::Chainsaw => {
            if let Some(kinds) = kinds.as_ref() {
                if !kinds.contains(&Kind::Chainsaw) {
                    return Ok(vec![]);
                }
            }
            let rule = chainsaw::load(path)?;
            vec![Rule::Chainsaw(rule)]
        }
        Kind::Sigma => {
            if let Some(kinds) = kinds.as_ref() {
                if !kinds.contains(&Kind::Sigma) {
                    return Ok(vec![]);
                }
            }
            let sigma = match sigma::load(path)?
                .into_iter()
                .map(serde_yaml::from_value::<Sigma>)
                .collect::<Result<Vec<_>, _>>()
            {
                Ok(rules) => rules,
                Err(_) => {
                    anyhow::bail!("failed to load rule, run the linter for more information");
                }
            };
            sigma
                .into_iter()
                .map(|mut s| {
                    s.tau.detection.expression = optimiser::coalesce(
                        s.tau.detection.expression,
                        &s.tau.detection.identifiers,
                    );
                    s.tau.detection.identifiers.clear();
                    s.tau.detection.expression = optimiser::shake(s.tau.detection.expression);
                    s.tau.detection.expression = optimiser::rewrite(s.tau.detection.expression);
                    s.tau.detection.expression = optimiser::matrix(s.tau.detection.expression);
                    Rule::Sigma(s)
                })
                .collect()
        }
    };
    if let Some(levels) = levels.as_ref() {
        rules.retain(|r| levels.contains(r.level()));
    }
    if let Some(statuses) = statuses.as_ref() {
        rules.retain(|r| statuses.contains(r.status()));
    }
    Ok(rules)
}

pub fn lint(kind: &Kind, path: &Path) -> crate::Result<Vec<Filter>> {
    if let Some(x) = path.extension() {
        if x != "yml" && x != "yaml" {
            anyhow::bail!("rule must have a yaml file extension");
        }
    }
    let detections = match kind {
        Kind::Chainsaw => match chainsaw::load(path) {
            Ok(rule) => {
                vec![rule.filter]
            }
            Err(e) => {
                anyhow::bail!("{}", e);
            }
        },
        Kind::Sigma => match sigma::load(path) {
            Ok(yamls) => {
                let sigma = yamls
                    .into_iter()
                    .map(serde_yaml::from_value::<Sigma>)
                    .collect::<Result<Vec<_>, _>>()?;
                sigma
                    .into_iter()
                    .map(|r| Filter::Detection(r.tau.detection))
                    .collect()
            }
            Err(e) => {
                if let Some(source) = e.source() {
                    anyhow::bail!("{} - {}", e, source);
                } else {
                    anyhow::bail!("{}", e);
                }
            }
        },
    };
    Ok(detections)
}
