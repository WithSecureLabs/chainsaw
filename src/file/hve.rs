use anyhow::Error;
use chrono::{NaiveDateTime, DateTime, Utc, Datelike};
use notatin::{
    cell_key_node::CellKeyNode,
    parser::{Parser as HveParser, ParserIterator},
    parser_builder::ParserBuilder,
};
use serde_json::Value as Json;
use std::{path::Path, collections::HashMap, fmt::Display};

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

pub struct ShimCacheEntry {
    signature: String,
    path_size: usize,
    path: String,
    last_modified_time: Option<DateTime<Utc>>,
    data_size: usize,
    data: Vec<u8>,
    executed: Option<bool>,
    // controlset:
    cache_entry_position: u32,
}


impl Display for ShimCacheEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.last_modified_time {
            Some(ts) => write!(f, "{}:\t{:?}, {}", self.cache_entry_position, ts, self.path),
            None => write!(f, "{}:\t {}", self.cache_entry_position, self.path),
        }
    }
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

    //TODO: parsing of different versions of Amcache
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

    pub fn parse_shimcache (&mut self) -> anyhow::Result<Vec<ShimCacheEntry>> {
        let shimcache_key = self
            .inner
            //TODO: get control set dynamically instead of hardcoded
            .get_key("ControlSet001\\Control\\Session Manager\\AppCompatCache", false)?.unwrap();

        let shimcache_cell_value = shimcache_key.get_value("AppCompatCache")
            .ok_or(anyhow::anyhow!("AppCompatCache key not found!"))?.get_content().0;
        let shimcache_bytes = match shimcache_cell_value {
            notatin::cell_value::CellValue::Binary(bytes) => bytes,
            _ => anyhow::bail!("Shimcache value was not of type Binary!"),
        };

        let mut shimcache_entries: Vec<ShimCacheEntry> = Vec::new();

        
        let sig_num = u32::from_le_bytes(shimcache_bytes[0..4].try_into()?);
        let cache_signature = std::str::from_utf8(&shimcache_bytes[128..132])?;
        println!("Signature: {cache_signature}, Signature number: {:#x}", sig_num);

        if sig_num == 0xdeadbeef // win xp
        || sig_num == 0xbadc0ffe // win vista
        {
            anyhow::bail!("Unsupported windows shimcache version!")
        }
        // Windows 7 shimcache
        else if sig_num == 0xbadc0fee {
            anyhow::bail!("Windows 7 shimcache parsing not yet implemented!")
        }
        // Windows 8 shimcache
        else if cache_signature == "00ts" {
            anyhow::bail!("Windows 8 shimcache parsing not yet implemented!")
        }
        // Windows 8.1 shimcache
        else if cache_signature == "10ts" {
            anyhow::bail!("Windows 8.1 shimcache parsing not yet implemented!")
        }
        else {
            // windows 10 check
            let offset_to_records = sig_num.clone() as usize;
            let cache_signature = std::str::from_utf8(&shimcache_bytes[offset_to_records..offset_to_records+4])?;
            if cache_signature == "10ts" {
                let mut index = offset_to_records.clone();
                let mut cache_entry_position = 0;
                let len = shimcache_bytes.len();
                while index < len {
                    let signature = std::str::from_utf8(&shimcache_bytes[index..index+4])?.to_string();
                    if signature != "10ts" {
                        break;
                    }
                    index += 4;
                    // skip 4 unknown
                    index += 4;
                    let _cache_entry_size = u32::from_le_bytes(shimcache_bytes[index..index+4].try_into()?);
                    index += 4;
                    let path_size = u16::from_le_bytes(shimcache_bytes[index..index+2].try_into()?) as usize;
                    index += 2;
                    let path = std::str::from_utf8(&shimcache_bytes[index..index+path_size])?.to_string();
                    index += path_size;
                    let last_modified_time_utc_win32 = u64::from_le_bytes(shimcache_bytes[index..index+8].try_into()?);
                    index += 8;
                    let data_size = u32::from_le_bytes(shimcache_bytes[index..index+4].try_into()?) as usize;
                    index += 4;
                    let data = shimcache_bytes[index..index+data_size].to_vec();
                    index += data_size;

                    let last_modified_time = if last_modified_time_utc_win32 != 0 {
                        let last_modified_time_utc = win32_ts_to_datetime(last_modified_time_utc_win32)
                            .ok_or(anyhow::anyhow!("Could not parse shimcache entry timestamp!"))?;
                        let last_modified_date_time = DateTime::<Utc>::from_utc(last_modified_time_utc, Utc);
                        Some(last_modified_date_time)
                    } else {
                        None
                    };

                    let cache_entry = ShimCacheEntry {
                        cache_entry_position,
                        data,
                        data_size,
                        executed: None,
                        last_modified_time,
                        path,
                        path_size,
                        signature,
                    };

                    shimcache_entries.push(cache_entry);
                    cache_entry_position += 1;
                }
            }
        }

        Ok(shimcache_entries)
    }
}

fn win32_ts_to_datetime(ts_win32: u64) -> Option<NaiveDateTime> {
    let ts_unix = ((ts_win32 / 10_000) as i64 - 11644473600000);
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

    #[test]
    fn shimcache_parsing_works_win7() -> Result<(), Error> {
        let mut parser = Parser::load(&Path::new(
            "/mnt/hgfs/vm_shared/Module 5 - Disk/cache/shimcache/SYSTEM",
        ))?;
        let shimcache_entries = parser.parse_shimcache()?;
        Ok(())
    }

    #[test]
    fn shimcache_parsing_works_win10() -> Result<(), Error> {
        let mut parser = Parser::load(&Path::new(
            "/mnt/hgfs/vm_shared/win10_vm_hives/shim/SYSTEM",
        ))?;
        let shimcache_entries = parser.parse_shimcache()?;
        for entry in shimcache_entries {
            println!("{entry}");
        }
        Ok(())
    }

}
