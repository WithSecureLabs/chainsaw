use std::{collections::HashMap};

use anyhow::{Result, bail};
use chrono::{NaiveDateTime, DateTime, Utc};
use notatin::{
    cell_key_node::CellKeyNode,
};

#[derive(Debug, Clone)]
pub struct InventoryApplicationFileArtifact {
    pub program_id: String,
    pub file_id: String,
    pub path: String,
    pub sha1_hash: Option<String>,
    pub link_date: Option<NaiveDateTime>,
    pub last_modified_ts: DateTime<Utc>,
}

#[derive(Debug)]
pub struct InventoryApplicationArtifact {
    pub program_id: String,
    pub program_name: String,
    pub install_date: Option<NaiveDateTime>,
    pub last_modified_ts: DateTime<Utc>,
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

pub struct AmcacheFileIterator<'a> {
    program_iterator: std::collections::hash_map::Iter<'a, String, ProgramArtifact>,
    file_iterator: Option<std::slice::Iter<'a, InventoryApplicationFileArtifact>>,
}

impl<'a> AmcacheFileIterator<'a> {
    fn new(amcache_artifact: &'a AmcacheArtifact) -> Self {
        let mut program_iterator = amcache_artifact.programs.iter();
        let first_program = program_iterator.next();
        let file_iterator = match first_program {
            Some((_program_id, program)) => Some(program.files.iter()),
            None => None,
        };
        Self {program_iterator, file_iterator}
    }
}

impl<'a> Iterator for AmcacheFileIterator<'a> {
    type Item = &'a InventoryApplicationFileArtifact;

    fn next(&mut self) -> Option<Self::Item> {
        let next_file = self.file_iterator.as_mut().map(|i| i.next()).flatten();
        match next_file {
            Some(file) => Some(file),
            None => {
                while let Some((_program_id, program)) = self.program_iterator.next() {
                    let mut file_iterator = program.files.iter();
                    let next_file = file_iterator.next();
                    self.file_iterator = Some(file_iterator);
                    if next_file.is_some() {
                        return next_file;
                    }
                }
                None
            }
        }
    }
}

impl AmcacheArtifact {
    pub fn iter_files(&self) -> AmcacheFileIterator {
        AmcacheFileIterator::new(self)
    }
}

impl super::Parser {
    // TODO: parsing of different versions of Amcache
    pub fn parse_amcache(&mut self) -> anyhow::Result<AmcacheArtifact> {
        fn string_value_from_key(key: &CellKeyNode, value_name: &str) -> Result<String> {
            let Some(key_value) = key.get_value(value_name) else {
                bail!(
                    "Could not extract value \"{}\" from key \"{}\"",
                    value_name, key.get_pretty_path()
                );
            };
            Ok(key_value.get_content().0.to_string())
        }

        let mut programs: HashMap<String, ProgramArtifact> = HashMap::new();

        // Parse registry key InventoryApplication
        let key_inventory_application_file = self
            .inner
            .get_key("Root\\InventoryApplication", false)?;
        let Some(mut node_inventory_application) = key_inventory_application_file else {
            bail!("Could not find InventoryApplication key!");
        };
        let subkeys = node_inventory_application.read_sub_keys(&mut self.inner);
        for key in subkeys {
            let last_modified_ts = key.last_key_written_date_and_time();
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
                last_modified_ts,
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
            bail!("Could not find InventoryApplicationFile key!");
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

            // FileId is the SHA-1 hash of the file with "0000" prepended. Discard prefix
            let sha1_hash = if file_id.len() == 44 && &file_id[..4] == "0000" {
                Some(String::from(&file_id[4..]))
            } else {
                // In case unexpected value
                None
            };

            let last_modified_ts = key.last_key_written_date_and_time();
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

fn win_reg_str_ts_to_date_time(ts_str: &str) -> Result<NaiveDateTime> {
    Ok(NaiveDateTime::parse_from_str(ts_str, "%m/%d/%Y %H:%M:%S")?)
}