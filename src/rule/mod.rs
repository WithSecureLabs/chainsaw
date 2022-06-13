use std::fmt;
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::file::Kind as FileKind;

pub use self::chainsaw::{Filter, Rule as Chainsaw};
pub use self::sigma::Rule as Sigma;
pub use self::stalker::Rule as Stalker;

pub mod chainsaw;
pub mod sigma;
pub mod stalker;

#[derive(Clone, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Chainsaw,
    Sigma,
    Stalker,
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
            Self::Stalker => write!(f, "stalker"),
        }
    }
}

impl FromStr for Kind {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v = match s {
            "chainsaw" => Self::Chainsaw,
            "sigma" => Self::Sigma,
            "stalker" => Self::Stalker,
            _ => anyhow::bail!("unknown kind, must be: chainsaw, sigma or stalker"),
        };
        Ok(v)
    }
}

#[derive(Debug)]
pub struct Rule {
    pub chainsaw: Chainsaw,
    pub kind: Kind,
}

pub fn load_rule(path: &Path) -> crate::Result<Vec<Rule>> {
    if let Some(x) = path.extension() {
        if x != "yml" && x != "yaml" {
            anyhow::bail!("rule must have a yaml file extension");
        }
    }
    // This is a bit crude but we try all formats then report the errors...
    let rules = if let Ok(rule) = chainsaw::load(path) {
        vec![Rule {
            chainsaw: rule,
            kind: Kind::Chainsaw,
        }]
    } else if let Ok(rules) = sigma::load(path) {
        rules
            .into_iter()
            .filter_map(|r| serde_yaml::from_value(r).ok())
            .map(|rule: Sigma| Rule {
                chainsaw: Chainsaw {
                    name: rule.name,
                    group: "".to_owned(),
                    description: rule.description,
                    authors: rule.authors,
                    // NOTE: A fake value as this is not used for non chainsaw rules
                    kind: FileKind::Evtx,
                    level: rule
                        .level
                        .map(|l| match l.as_str() {
                            "critical" => chainsaw::Level::Critical,
                            "high" => chainsaw::Level::High,
                            "medium" => chainsaw::Level::Medium,
                            "low" => chainsaw::Level::Low,
                            _ => chainsaw::Level::Info,
                        })
                        .unwrap_or_else(|| chainsaw::Level::Info),
                    status: rule
                        .status
                        .map(|s| match s.as_str() {
                            "stable" => chainsaw::Status::Stable,
                            _ => chainsaw::Status::Testing,
                        })
                        .unwrap_or_else(|| chainsaw::Status::Testing),
                    timestamp: "".to_owned(),

                    fields: vec![],

                    filter: chainsaw::Filter::Detection(rule.tau.optimise(true, true).detection),

                    aggregate: None,
                },
                kind: Kind::Sigma,
            })
            .collect()
    } else if let Ok(rule) = stalker::load(path) {
        vec![Rule {
            chainsaw: Chainsaw {
                name: rule.tag,
                group: "".to_owned(),
                description: rule.description,
                authors: rule.authors,
                // NOTE: A fake value as this is not used for non chainsaw rules
                kind: FileKind::Evtx,
                level: match rule.level.as_str() {
                    "critical" => chainsaw::Level::Critical,
                    "high" => chainsaw::Level::High,
                    "medium" => chainsaw::Level::Medium,
                    "low" => chainsaw::Level::Low,
                    _ => chainsaw::Level::Info,
                },
                status: match rule.status.as_str() {
                    "stable" => chainsaw::Status::Stable,
                    _ => chainsaw::Status::Testing,
                },
                timestamp: "".to_owned(),

                fields: vec![],

                filter: chainsaw::Filter::Detection(rule.tau.optimise(true, true).detection),

                aggregate: None,
            },
            kind: Kind::Stalker,
        }]
    } else {
        anyhow::bail!("failed to load rule, run the linter for more information");
    };
    Ok(rules)
}

pub fn lint_rule(kind: &Kind, path: &Path) -> crate::Result<Vec<Filter>> {
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
                let file_name = match path.to_string_lossy().split('/').last() {
                    Some(e) => e.to_string(),
                    None => path.display().to_string(),
                };
                anyhow::bail!("{:?}: {}", file_name, e);
            }
        },
        Kind::Sigma => match sigma::load(path) {
            Ok(yamls) => yamls
                .into_iter()
                .filter_map(|y| serde_yaml::from_value::<Sigma>(y).ok())
                .map(|r| Filter::Detection(r.tau.detection))
                .collect(),
            Err(e) => {
                let file_name = match path.to_string_lossy().split('/').last() {
                    Some(e) => e.to_string(),
                    None => path.display().to_string(),
                };
                if let Some(source) = e.source() {
                    anyhow::bail!("{:?}: {} - {}", file_name, e, source);
                } else {
                    anyhow::bail!("{:?}: {}", file_name, e);
                }
            }
        },
        Kind::Stalker => match stalker::load(path) {
            Ok(rule) => {
                vec![Filter::Detection(rule.tau.detection)]
            }
            Err(e) => {
                let file_name = match path.to_string_lossy().split('/').last() {
                    Some(e) => e.to_string(),
                    None => path.display().to_string(),
                };
                anyhow::bail!("{:?}: {}", file_name, e);
            }
        },
    };
    Ok(detections)
}
