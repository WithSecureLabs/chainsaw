use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use notatin::cell_key_node::CellKeyNode;
use serde::Serialize;

use crate::file::win32_ts_to_datetime;

#[derive(Debug, Clone, Serialize)]
pub struct FileEntry {
    pub file_id: Option<String>,
    pub key_last_modified_ts: DateTime<Utc>,
    pub file_last_modified_ts: Option<DateTime<Utc>>,
    pub link_date: Option<DateTime<Utc>>,
    pub path: String,
    pub program_id: Option<String>,
    pub sha1_hash: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ProgramEntry {
    pub install_date: Option<DateTime<Utc>>,
    pub uninstall_date: Option<DateTime<Utc>>,
    pub last_modified_ts: DateTime<Utc>,
    pub program_id: String,
    pub program_name: String,
    pub version: String,
    pub root_directory_path: Option<String>,
    pub uninstall_string: Option<String>,
}

#[derive(Debug)]
pub struct AmcacheArtefact {
    pub file_entries: Vec<FileEntry>,
    pub program_entries: Vec<ProgramEntry>,
}

impl super::Parser {
    pub fn parse_amcache(&mut self) -> crate::Result<AmcacheArtefact> {
        /// A helper function for getting string values from registry keys
        fn string_value_from_key(
            key: &CellKeyNode,
            value_name: &str,
        ) -> crate::Result<Option<String>> {
            let Some(key_value) = key.get_value(value_name) else {
                return Ok(None);
            };
            Ok(match key_value.get_content().0 {
                notatin::cell_value::CellValue::String(str) => Some(str),
                _ => bail!(
                    "Value \"{}\" in key \"{}\" was not of type String!",
                    value_name,
                    key.get_pretty_path()
                ),
            })
        }

        let mut program_entries: Vec<ProgramEntry> = Vec::new();
        let mut file_entries: Vec<FileEntry> = Vec::new();

        let is_new_format: bool = self
            .inner
            .get_key(r"Root\InventoryApplicationFile", false)?
            .is_some();
        // TODO: extract all of the possible values, not just the ones that seem useful
        if is_new_format {
            /// A helper function for converting registry timestamp strings to DateTime
            fn win_reg_str_ts_to_date_time(ts_str: &str) -> crate::Result<DateTime<Utc>> {
                let naive = NaiveDateTime::parse_from_str(ts_str, "%m/%d/%Y %H:%M:%S")?;
                Ok(Utc.from_utc_datetime(&naive))
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
                let program_name = string_value_from_key(&key, "Name")?
                    .ok_or(anyhow!("Could not get Name for program {}", key.key_name))?;
                let version = string_value_from_key(&key, "Version")?
                    .ok_or(anyhow!("Could not get Version for program {}", program_id))?;

                let install_date = match string_value_from_key(&key, "InstallDate")?.as_deref() {
                    Some("") | None => None,
                    Some(v) => Some(win_reg_str_ts_to_date_time(v)?),
                };

                let root_directory_path = string_value_from_key(&key, "RootDirPath")?;
                let uninstall_string = string_value_from_key(&key, "UninstallString")?;

                let program_entry = ProgramEntry {
                    install_date,
                    last_modified_ts,
                    program_id: program_id.clone(),
                    program_name,
                    root_directory_path,
                    uninstall_string,
                    uninstall_date: None,
                    version,
                };

                program_entries.push(program_entry);
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
                let path = string_value_from_key(&key, "LowerCaseLongPath")?.ok_or(anyhow!(
                    "Could not get LowerCaseLongPath for file {}",
                    key.key_name
                ))?;
                let link_date_str = string_value_from_key(&key, "LinkDate")?
                    .ok_or(anyhow!("Could not get LinkDate for file {}", key.key_name))?;
                let link_date = if !link_date_str.is_empty() {
                    // NOTE: Sometimes the link date is just completely invalid, in that case we
                    // just none it rather than throwing an error. We should log this out, but for
                    // now this is sufficient.
                    win_reg_str_ts_to_date_time(link_date_str.as_str()).ok()
                } else {
                    None
                };

                // FileId is the SHA-1 hash of the file with "0000" prepended. Discard prefix
                let sha1_hash = file_id.as_ref().and_then(|id| {
                    if id.len() == 44 && &id[..4] == "0000" {
                        Some(String::from(&id[4..]))
                    } else {
                        // In case unexpected value
                        None
                    }
                });

                let key_last_modified_ts = key.last_key_written_date_and_time();
                let file_entry = FileEntry {
                    program_id,
                    file_id,
                    path,
                    sha1_hash,
                    link_date,
                    key_last_modified_ts,
                    file_last_modified_ts: None,
                };
                file_entries.push(file_entry);
            }
        // Older amcache format
        } else {
            /// A helper function for extracting unix timestamps from key values
            fn unix_ts_from_key(
                key: &CellKeyNode,
                value_name: &str,
            ) -> crate::Result<Option<DateTime<Utc>>> {
                let Some(key_value) = key.get_value(value_name) else {
                    return Ok(None);
                };
                Ok(match key_value.get_content().0 {
                    notatin::cell_value::CellValue::U32(num) => {
                        if num == 0 {
                            return Ok(None);
                        }
                        let datetime = DateTime::from_timestamp(num as i64, 0)
                            .expect("unix timestamp our of range");
                        Some(datetime)
                    }
                    notatin::cell_value::CellValue::U64(num) => {
                        if num == 0 {
                            return Ok(None);
                        }
                        let datetime = DateTime::from_timestamp(num as i64, 0)
                            .expect("unix timestamp our of range");
                        Some(datetime)
                    }
                    _ => bail!(
                        "Value \"{}\" in key \"{}\" was not of type U32 or U64!",
                        value_name,
                        key.get_pretty_path()
                    ),
                })
            }

            // Get and parse data from Programs
            let mut key_programs = self
                .inner
                .get_key(r"Root\Programs", false)?
                .ok_or(anyhow!("Programs key not found in amcache!"))?;
            let subkeys = key_programs.read_sub_keys(&mut self.inner);
            for key in subkeys {
                let last_modified_ts = key.last_key_written_date_and_time();
                let program_id = key.key_name.clone();
                let program_name = string_value_from_key(&key, "0")?.ok_or(anyhow!(
                    "Could not get \"0\" (program_name) for {}",
                    key.key_name
                ))?;
                let version = string_value_from_key(&key, "1")?.ok_or(anyhow!(
                    "Could not get \"0\" (version) for {}",
                    key.key_name
                ))?;
                let install_date = unix_ts_from_key(&key, "a")?;
                let uninstall_date = unix_ts_from_key(&key, "b")?;

                let program_entry = ProgramEntry {
                    install_date,
                    last_modified_ts,
                    program_id,
                    program_name,
                    root_directory_path: None,
                    uninstall_date,
                    uninstall_string: None,
                    version,
                };
                program_entries.push(program_entry);
            }

            // Get and parse data from File
            let mut key_file = self
                .inner
                .get_key(r"Root\File", false)?
                .ok_or(anyhow!("File key not found in amcache!"))?;
            let volume_keys = key_file.read_sub_keys(&mut self.inner);
            for mut key_volume in volume_keys {
                let file_keys = key_volume.read_sub_keys(&mut self.inner);
                for key_file in file_keys {
                    let program_id = string_value_from_key(&key_file, "100")?;
                    let file_id = string_value_from_key(&key_file, "101")?;
                    let path = string_value_from_key(&key_file, "15")?.ok_or(anyhow!(
                        "Could not get \"15\" (path) for file {}",
                        key_file.key_name
                    ))?;
                    let link_date = unix_ts_from_key(&key_file, "f")?; // compilation_date
                    let file_last_modified_ts = if let Some(value) = key_file.get_value("17") {
                        if let (notatin::cell_value::CellValue::U64(ts), _logs) =
                            value.get_content()
                        {
                            let datetime = win32_ts_to_datetime(ts)?;
                            Some(datetime)
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    // FileId is the SHA-1 hash of the file with "0000" prepended. Discard prefix
                    let sha1_hash = file_id.as_ref().and_then(|id| {
                        if id.len() == 44 && &id[..4] == "0000" {
                            Some(String::from(&id[4..]))
                        } else {
                            // In case unexpected value
                            None
                        }
                    });

                    let key_last_modified_ts = key_file.last_key_written_date_and_time();
                    let file_entry = FileEntry {
                        program_id,
                        file_id,
                        path,
                        sha1_hash,
                        link_date,
                        key_last_modified_ts,
                        file_last_modified_ts,
                    };
                    file_entries.push(file_entry);
                }
            }
        }

        Ok(AmcacheArtefact {
            file_entries,
            program_entries,
        })
    }
}
