use std::path::PathBuf;
use std::str::FromStr;

use serde::Deserialize;

pub use self::chainsaw::Rule;

pub mod chainsaw;
pub mod sigma;
pub mod stalker;

#[derive(Debug, Deserialize)]
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

pub fn load_rule(kind: &Kind, path: &PathBuf) -> crate::Result<Vec<Rule>> {
    if let Some(x) = path.extension() {
        if x != "yml" && x != "yaml" {
            anyhow::bail!("rule must have a yaml file extension");
        }
    }
    let rules = match kind {
        Kind::Chainsaw => {
            unimplemented!()
        }
        Kind::Sigma => match sigma::load(&path) {
            Ok(rules) => rules
                .into_iter()
                .filter_map(|r| serde_yaml::from_value(r).ok())
                .collect(),
            Err(e) => anyhow::bail!(e),
        },
        Kind::Stalker => match stalker::load(&path) {
            Ok(rule) => vec![rule],
            Err(e) => anyhow::bail!(e),
        },
    };
    Ok(rules)
}

pub fn lint_rule(kind: &Kind, path: &PathBuf) -> crate::Result<()> {
    if let Some(x) = path.extension() {
        if x != "yml" && x != "yaml" {
            anyhow::bail!("rule must have a yaml file extension");
        }
    }
    match kind {
        Kind::Chainsaw => {
            unimplemented!()
        }
        Kind::Sigma => {
            if let Err(e) = sigma::load(&path) {
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
        }
        Kind::Stalker => {
            if let Err(e) = stalker::load(&path) {
                let file_name = match path.to_string_lossy().split('/').last() {
                    Some(e) => e.to_string(),
                    None => path.display().to_string(),
                };
                anyhow::bail!("{:?}: {}", file_name, e);
            }
        }
    }
    Ok(())
}
