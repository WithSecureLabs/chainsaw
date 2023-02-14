use std::{collections::HashMap};

use anyhow::{Result, bail};
use chrono::{NaiveDateTime, DateTime, Utc};
use notatin::{
    cell_key_node::CellKeyNode,
};

#[derive(Debug, Clone)]
pub struct FileEntry {
    pub file_id: String,
    pub last_modified_ts: DateTime<Utc>,
    pub link_date: Option<DateTime<Utc>>,
    pub path: String,
    pub program_id: String,
    pub sha1_hash: Option<String>,
}

#[derive(Debug)]
pub struct ProgramEntry {
    pub install_date: Option<DateTime<Utc>>,
    pub last_modified_ts: DateTime<Utc>,
    pub program_id: String,
    pub program_name: String,
}
#[derive(Debug)]
pub struct ProgramArtifact {
    pub files: Vec<FileEntry>,
    pub program_entry: Option<ProgramEntry>,
    pub program_id: String,
}

impl ProgramArtifact {
    pub fn with_program_entry(program_entry: ProgramEntry) -> Self {
        let program_id = program_entry.program_id.clone();
        Self {
            files: Vec::new(),
            program_entry: Some(program_entry),
            program_id,
        }
    }
    pub fn with_file(file: FileEntry) -> Self {
        let program_id = file.program_id.clone();
        Self {
            files: vec![file],
            program_entry: None,
            program_id,
        }
    }
}

#[derive(Debug)]
pub struct AmcacheArtifact {
    pub is_new_format: bool,
    pub programs: HashMap<String, ProgramArtifact>,
}

pub struct AmcacheFileIterator<'a> {
    file_iterator: Option<std::slice::Iter<'a, FileEntry>>,
    program_iterator: std::collections::hash_map::Iter<'a, String, ProgramArtifact>,
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
    type Item = &'a FileEntry;

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
    pub fn parse_amcache(&mut self) -> Result<AmcacheArtifact> {
        /// A helper function for getting string values from registry keys
        fn string_value_from_key(key: &CellKeyNode, value_name: &str) -> Result<String> {
            let Some(key_value) = key.get_value(value_name) else {
                bail!(
                    "Could not extract value \"{}\" from key \"{}\"",
                    value_name, key.get_pretty_path()
                );
            };
            Ok(match key_value.get_content().0 {
                notatin::cell_value::CellValue::String(str) => str,
                _ => bail!(
                    "Value \"{}\" in key \"{}\" was not of type String!",
                    value_name, key.get_pretty_path()
                ),
            })
        }

        let mut programs: HashMap<String, ProgramArtifact> = HashMap::new();

        let is_new_format: bool = self.inner.get_key(r"Root\InventoryApplicationFile", false)?.is_some();
        // TODO: extract all of the possible values, not just the ones that seem useful
        if is_new_format {
            /// A helper function for converting registry timestamp strings to DateTime
            fn win_reg_str_ts_to_date_time(ts_str: &str) -> Result<DateTime<Utc>> {
                let naive = NaiveDateTime::parse_from_str(ts_str, "%m/%d/%Y %H:%M:%S")?;
                Ok(DateTime::<Utc>::from_utc(naive, Utc))
            }

            // Get and parse data from InventoryApplication
            let mut key_inventory_application_file = self
                .inner
                .get_key(r"Root\InventoryApplication", false)?
                .ok_or(anyhow!("Could not find InventoryApplication key!"))?;
            let subkeys = key_inventory_application_file.read_sub_keys(&mut self.inner);
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

                let program_entry = ProgramEntry {
                    last_modified_ts,
                    program_id,
                    program_name,
                    install_date,
                };
                
                let program_artifact = ProgramArtifact::with_program_entry(program_entry);
                programs.insert(program_artifact.program_id.clone(), program_artifact);
            }
    
            // Get and parse data from InventoryApplicationFile
            let mut key_inventory_application_file = self
                .inner
                .get_key(r"Root\InventoryApplicationFile", false)?
                .ok_or(anyhow!("Could not find InventoryApplicationFile key!"))?;
            let subkeys = key_inventory_application_file.read_sub_keys(&mut self.inner);
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
                let file_entry = FileEntry {
                    program_id,
                    file_id,
                    path,
                    sha1_hash,
                    link_date,
                    last_modified_ts,
                };
                match programs.get_mut(&file_entry.program_id) {
                    Some(program) => {
                        program.files.push(file_entry);
                    },
                    None => {
                        let program = ProgramArtifact::with_file(file_entry);
                        programs.insert(program.program_id.clone(), program);
                    }
                }
            }
        // Older amcache format
        } else {
            // TODO: verify correct behavior with test files
            /// A helper function for extracting unix timestamps from key values
            fn unix_ts_from_key(key: &CellKeyNode, value_name: &str) -> Result<DateTime<Utc>> {
                let Some(key_value) = key.get_value(value_name) else {
                    bail!(
                        "Could not extract value \"{}\" from key \"{}\"",
                        value_name, key.get_pretty_path()
                    );
                };
                Ok(match key_value.get_content().0 {
                    notatin::cell_value::CellValue::U32(num) => {
                        let naive = NaiveDateTime::from_timestamp_opt(num as i64, 0)
                            .expect("unix timestamp our of range");
                        DateTime::<Utc>::from_utc(naive, Utc)
                    }
                    _ => bail!(
                        "Value \"{}\" in key \"{}\" was not of type U32!",
                        value_name, key.get_pretty_path()
                    ),
                })
            }

            // Get and parse data from Programs
            let mut key_programs = self.inner.get_key(r"Root\Programs", false)?
                .ok_or(anyhow!("Programs key not found in amcache!"))?;
            let subkeys = key_programs.read_sub_keys(&mut self.inner);
            for key in subkeys {
                let last_modified_ts = key.last_key_written_date_and_time();
                let program_id = key.key_name.clone();
                let program_name = string_value_from_key(&key, "0")?;
                let install_date = Some(unix_ts_from_key(&key, "a")?);

                let program_entry = ProgramEntry {
                    last_modified_ts,
                    program_id,
                    program_name,
                    install_date,
                };
                let program_artifact = ProgramArtifact::with_program_entry(program_entry);
                programs.insert(program_artifact.program_id.clone(), program_artifact);
            }

            // Get and parse data from File
            let mut key_file = self.inner.get_key(r"Root\File", false)?
                .ok_or(anyhow!("File key not found in amcache!"))?;
            let subkeys = key_file.read_sub_keys(&mut self.inner);
            for key in subkeys {
                let program_id = string_value_from_key(&key, "100")?;
                let file_id = string_value_from_key(&key, "101")?;
                let path = string_value_from_key(&key, "15")?;
                let link_date = Some(unix_ts_from_key(&key, "f")?); // compilation_date
    
                // FileId is the SHA-1 hash of the file with "0000" prepended. Discard prefix
                let sha1_hash = if file_id.len() == 44 && &file_id[..4] == "0000" {
                    Some(String::from(&file_id[4..]))
                } else {
                    // In case unexpected value
                    None
                };
    
                let last_modified_ts = key.last_key_written_date_and_time();
                let file_entry = FileEntry {
                    program_id,
                    file_id,
                    path,
                    sha1_hash,
                    link_date,
                    last_modified_ts,
                };
                match programs.get_mut(&file_entry.program_id) {
                    Some(program) => {
                        program.files.push(file_entry);
                    },
                    None => {
                        let program = ProgramArtifact::with_file(file_entry);
                        programs.insert(program.program_id.clone(), program);
                    }
                }
            }
        }

        Ok(AmcacheArtifact { programs, is_new_format })
    }
}
