use std::fs::File;
use std::io::Read;
use std::path::Path;

use serde::Deserialize;
use tau_engine::Rule as Tau;

use crate::rule::Rule;

#[derive(Clone, Deserialize)]
pub struct Stalker {
    tag: String,
    tau: Tau,
    level: String,
    status: String,
    authors: Vec<String>,
}

impl From<Stalker> for Rule {
    fn from(stalker: Stalker) -> Self {
        Self {
            tag: stalker.tag,
            level: stalker.level,
            status: stalker.status,
            tau: stalker.tau,
            authors: stalker.authors,
        }
    }
}

pub fn load(rule: &Path) -> crate::Result<Rule> {
    let mut file = File::open(rule)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let stalker: Stalker = serde_yaml::from_str(&contents)?;
    Ok(Rule::from(stalker))
}
