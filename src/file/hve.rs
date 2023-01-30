use anyhow::Error;
use chrono::NaiveDateTime;
use notatin::{
    cell_key_node::CellKeyNode,
    parser::{Parser as HveParser, ParserIterator},
    parser_builder::ParserBuilder,
};
use serde_json::Value as Json;
use std::{path::Path, collections::HashMap};

pub type Hve = Json;

pub struct Parser {
    pub inner: HveParser,
}

#[derive(Debug)]
pub struct InventoryApplicationFileArtifact {
    pub program_id: String,
    pub file_id: String,
    pub path: String,
    pub sha1_hash: String,
    pub link_date: Option<NaiveDateTime>,
    pub last_modified_ts: NaiveDateTime,
}

#[derive(Debug)]
pub struct InventoryApplicationArtifact {
    pub program_id: String,
    pub program_name: String,
    pub install_date: Option<NaiveDateTime>,
}
#[derive(Debug)]
pub struct ProgramArtifact {
    pub program_id: String,
    pub application_artifact: Option<InventoryApplicationArtifact>,
    pub files: Vec<InventoryApplicationFileArtifact>,
}

impl ProgramArtifact {
    pub fn new(program_id: &str) -> Self {
        Self {
            program_id: program_id.to_string(),
            application_artifact: None,
            files: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct AmcacheArtifact {
    pub programs: HashMap<String, ProgramArtifact>,
}

impl Parser {
    pub fn load(file: &Path) -> crate::Result<Self> {
        let path = match file.to_str() {
            Some(path) => path,
            None => anyhow::bail!("Could not convert path to string!"),
        };
        let parser: HveParser = ParserBuilder::from_path(String::from(path))
            .recover_deleted(false)
            .build()?;

        Ok(Self { inner: parser })
    }

    pub fn parse(&mut self) -> impl Iterator<Item = Result<Json, Error>> + '_ {
        ParserIterator::new(&self.inner)
            .iter()
            .map(|c| match serde_json::to_value(c) {
                Ok(json) => Ok(json),
                Err(e) => anyhow::bail!(e),
            })
    }

    pub fn parse_amcache(&mut self) -> anyhow::Result<AmcacheArtifact> {
        fn string_value_from_key(key: &CellKeyNode, value_name: &str) -> Result<String, Error> {
            let Some(key_value) = key.get_value(value_name) else {
                return Err(anyhow::anyhow!(
                    "Could not extract value \"{}\" from key \"{}\"",
                    value_name, key.get_pretty_path()
                ));
            };
            Ok(key_value.get_content().0.to_string())
        }

        let mut programs: HashMap<String, ProgramArtifact> = HashMap::new();

        // Parse registry key InventoryApplication
        let key_inventory_application_file = self
            .inner
            .get_key("Root\\InventoryApplication", false)?;
        let Some(mut node_inventory_application) = key_inventory_application_file else {
            return Err(anyhow::anyhow!("Could not find InventoryApplication key!"));
        };
        let subkeys = node_inventory_application.read_sub_keys(&mut self.inner);
        for key in subkeys {
            let program_id = key.key_name.clone();
            let program_name = string_value_from_key(&key, "Name")?;
            let install_date = string_value_from_key(&key, "InstallDate")?;

            let install_date = if !install_date.is_empty() {
                Some(win_reg_str_ts_to_date_time(install_date.as_str())?)
            } else {
                None
            };

            let mut program_artifact = ProgramArtifact::new(&program_id);

            let app_artifact = InventoryApplicationArtifact {
                program_id,
                program_name,
                install_date,
            };

            program_artifact.application_artifact = Some(app_artifact);

            programs.insert(program_artifact.program_id.clone(), program_artifact);
        }

        // Parse registry key InventoryApplicationFile
        let key_inventory_application_file = self
            .inner
            .get_key("Root\\InventoryApplicationFile", false)?;
        let Some(mut node_inventory_application_file) = key_inventory_application_file else {
            return Err(anyhow::anyhow!("Could not find InventoryApplicationFile key!"));
        };
        let subkeys = node_inventory_application_file.read_sub_keys(&mut self.inner);
        for key in subkeys {
            let program_id = string_value_from_key(&key, "ProgramId")?;
            let file_id = string_value_from_key(&key, "FileId")?;
            let path = string_value_from_key(&key, "LowerCaseLongPath")?;
            let link_date_str = string_value_from_key(&key, "LinkDate")?;
            let link_date = if !link_date_str.is_empty() {
                Some(win_reg_str_ts_to_date_time(link_date_str.as_str())?)
            } else {
                None
            };

            let sha1_hash = String::from(&file_id[4..]);

            let last_modified_ts = win32_ts_to_datetime(key.detail.last_key_written_date_and_time())
                .ok_or(anyhow::anyhow!("Could not parse timestamp!"))?;
            let file_artifact = InventoryApplicationFileArtifact {
                program_id,
                file_id,
                path,
                sha1_hash,
                link_date,
                last_modified_ts,
            };
            match programs.get_mut(&file_artifact.program_id) {
                Some(program) => {
                    program.files.push(file_artifact);
                },
                None => {
                    let mut program = ProgramArtifact::new(&file_artifact.program_id);
                    program.files.push(file_artifact);
                    programs.insert(program.program_id.clone(), program);
                }
            }
        }

        Ok(AmcacheArtifact { programs })
    }
}

fn win32_ts_to_datetime(ts_win32: u64) -> Option<NaiveDateTime> {
    let ts_unix = ((ts_win32 / 10_000) - 11644473600000) as i64;
    chrono::prelude::NaiveDateTime::from_timestamp_millis(ts_unix)
}

fn win_reg_str_ts_to_date_time(ts_str: &str) -> anyhow::Result<NaiveDateTime> {
    Ok(NaiveDateTime::parse_from_str(ts_str, "%m/%d/%Y %H:%M:%S")?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amcache_parsing_works() -> Result<(), Error> {
        let mut parser = Parser::load(&Path::new(
            "/mnt/hgfs/vm_shared/Module 5 - Disk/cache/amcache/Amcache.hve",
        ))?;
        let artifact_map = parser.parse_amcache()?;
        println!("{:#?}", artifact_map);
        Ok(())
    }
}
