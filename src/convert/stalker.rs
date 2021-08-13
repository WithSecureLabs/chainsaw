use crate::hunt::ChainsawRule;
use anyhow::Result;
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Clone, Deserialize)]
pub struct Stalker {
	tag: String,
	tau: tau_engine::Rule,
	level: String,
	status: String,
}

impl From<Stalker> for ChainsawRule {
	fn from(stalker: Stalker) -> Self {
		Self {
			tag: stalker.tag,
			level: Some(stalker.level),
			status: Some(stalker.status),
			logic: stalker.tau,
		}
	}
}

pub fn load(rule: &Path) -> Result<ChainsawRule> {
	let mut file = File::open(rule)?;
	let mut contents = String::new();
	file.read_to_string(&mut contents)?;

	let stalker: Stalker = serde_yaml::from_str(&contents)?;
	Ok(ChainsawRule::from(stalker))
}
