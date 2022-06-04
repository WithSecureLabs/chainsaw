use std::fs::File;
use std::io::Read;
use std::path::Path;

use serde::Deserialize;
use tau_engine::Rule as Tau;

#[derive(Clone, Debug, Deserialize)]
pub struct Rule {
    pub tag: String,
    pub tau: Tau,
    pub description: String,
    pub level: String,
    pub status: String,
    pub authors: Vec<String>,
}

pub fn load(rule: &Path) -> crate::Result<Rule> {
    let mut file = File::open(rule)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let rule: Rule = serde_yaml::from_str(&contents)?;
    Ok(rule)
}
