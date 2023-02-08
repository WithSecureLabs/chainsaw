use anyhow::{Result, bail, anyhow};
use chrono::{NaiveDateTime, DateTime, Utc};
use notatin::{
    cell_key_node::CellKeyNode,
    parser::{Parser as HveParser, ParserIterator},
    parser_builder::ParserBuilder,
};
use regex::Regex;
use serde_json::Value as Json;
use std::{path::{PathBuf, Path}, collections::HashMap, fmt::Display};

pub type Hve = Json;

pub struct Parser {
    pub inner: HveParser,
}

#[derive(Debug, Clone)]
pub struct InventoryApplicationFileArtifact {
    pub program_id: String,
    pub file_id: String,
    pub path: String,
    pub sha1_hash: String,
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

#[derive(Debug)]
pub enum ProgramType {
    Program {
        program_name: String,
        full_string: String,
    },
    Executable {
        path: String
    }
}

#[derive(Debug)]
pub struct ShimCacheEntry {
    pub signature: String,
    pub path_size: usize,
    pub program: ProgramType,
    pub last_modified_ts: Option<DateTime<Utc>>,
    pub data_size: usize,
    pub data: Vec<u8>,
    pub executed: Option<bool>,
    // controlset:
    pub cache_entry_position: u32,
}


impl Display for ShimCacheEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let path_or_name = match &self.program {
            ProgramType::Program { program_name, .. } => program_name,
            ProgramType::Executable { path } => path,
        };
        match self.last_modified_ts {
            Some(ts) => write!(f, "{}:\t{:?}, {}", self.cache_entry_position, ts, path_or_name),
            None => write!(f, "{}:\t {}", self.cache_entry_position, path_or_name),
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
        let next_file = match &mut self.file_iterator {
            Some(iterator) => iterator.next(),
            None => None,
        };
        match next_file {
            Some(file) => Some(file),
            None => {
                loop {
                    let next_program = self.program_iterator.next();
                    match next_program {
                        None => break None,
                        Some((_program_id, program)) => {
                            let mut file_iterator = program.files.iter();
                            let next_file = file_iterator.next();
                            self.file_iterator = Some(file_iterator);
                            match next_file {
                                None => continue,
                                Some(file) => break Some(file),
                            }
                        }
                    }
                }
            }
        }
    }
}

impl AmcacheArtifact {
    pub fn iter_files(&self) -> AmcacheFileIterator {
        AmcacheFileIterator::new(self)
    }
}

impl Parser {
    pub fn load(path: &Path) -> crate::Result<Self> {
        let parser: HveParser = ParserBuilder::from_path(PathBuf::from(path))
            .recover_deleted(false)
            .build()?;

        Ok(Self { inner: parser })
    }

    pub fn parse(&mut self) -> impl Iterator<Item = Result<Json>> + '_ {
        ParserIterator::new(&self.inner)
            .iter()
            .map(|c| match serde_json::to_value(c) {
                Ok(json) => Ok(json),
                Err(e) => bail!(e),
            })
    }

    //TODO: parsing of different versions of Amcache
    pub fn parse_amcache(&mut self) -> anyhow::Result<AmcacheArtifact> {
        fn string_value_from_key(key: &CellKeyNode, value_name: &str) -> Result<String> {
            let Some(key_value) = key.get_value(value_name) else {
                return Err(anyhow!(
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

            let sha1_hash = String::from(&file_id[4..]);

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

    pub fn parse_shimcache (&mut self) -> Result<Vec<ShimCacheEntry>> {
        let shimcache_key = self
            .inner
            //TODO: get control set dynamically instead of hardcoded
            .get_key("ControlSet001\\Control\\Session Manager\\AppCompatCache", false)?.unwrap();

        let shimcache_cell_value = shimcache_key.get_value("AppCompatCache")
            .ok_or(anyhow!("AppCompatCache key not found!"))?.get_content().0;
        let shimcache_bytes = match shimcache_cell_value {
            notatin::cell_value::CellValue::Binary(bytes) => bytes,
            _ => bail!("Shimcache value was not of type Binary!"),
        };

        let mut shimcache_entries: Vec<ShimCacheEntry> = Vec::new();

        
        let sig_num = u32::from_le_bytes(shimcache_bytes[0..4].try_into()?);
        let cache_signature = std::str::from_utf8(&shimcache_bytes[128..132])?;

        if sig_num == 0xdeadbeef // win xp
        || sig_num == 0xbadc0ffe // win vista
        {
            bail!("Unsupported windows shimcache version!")
        }
        // Windows 7 shimcache
        else if sig_num == 0xbadc0fee {
            bail!("Windows 7 shimcache parsing not yet implemented!")
        }
        // Windows 8 shimcache
        else if cache_signature == "00ts" {
            bail!("Windows 8 shimcache parsing not yet implemented!")
        }
        // Windows 8.1 shimcache
        else if cache_signature == "10ts" {
            bail!("Windows 8.1 shimcache parsing not yet implemented!")
        }
        else {
            let offset_to_records = sig_num.clone() as usize;
            let cache_signature = std::str::from_utf8(&shimcache_bytes[offset_to_records..offset_to_records+4])?;
            // Windows 10 shimcache
            if cache_signature == "10ts" {
                let re = Regex::new(r"^([0-9a-f]{8})\s+([0-9a-f]{16})\s+([0-9a-f]{16})\s+([\w]{4})\s+([\w.]+)\s+(\w+)\s*(\w*)$").unwrap();
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
                    let path = utf16_to_string(&shimcache_bytes[index..index+path_size])?;
                    let program: ProgramType;
                    if re.is_match(&path) {
                        let program_name = re.captures(&path).unwrap().get(5).unwrap().as_str().to_string();
                        program = ProgramType::Program { program_name, full_string: path };
                    } else {
                        program = ProgramType::Executable { path };
                    }
                    index += path_size;
                    let last_modified_time_utc_win32 = u64::from_le_bytes(shimcache_bytes[index..index+8].try_into()?);
                    index += 8;
                    let data_size = u32::from_le_bytes(shimcache_bytes[index..index+4].try_into()?) as usize;
                    index += 4;
                    let data = shimcache_bytes[index..index+data_size].to_vec();
                    index += data_size;

                    let last_modified_ts = if last_modified_time_utc_win32 != 0 {
                        let last_modified_time_utc = win32_ts_to_datetime(last_modified_time_utc_win32)?;
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
                        last_modified_ts,
                        program,
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

fn utf16_to_string(bytes: &[u8]) -> Result<String> {
    let bytes_vec = Vec::from_iter(bytes);
    let chunk_iterator = bytes_vec
        .chunks_exact(2)
        .into_iter();
    if chunk_iterator.remainder().len() > 0 {
        bail!("Bytes did not align to 16 bits!");
    }
    let word_vector: Vec<u16> = chunk_iterator
        .map(|a| u16::from_ne_bytes([*a[0], *a[1]]))
        .collect();
    let title = word_vector.as_slice();
    Ok(String::from_utf16(title)?)
}

fn win32_ts_to_datetime(ts_win32: u64) -> Result<NaiveDateTime> {
    let ts_unix = (ts_win32 / 10_000) as i64 - 11644473600000;
    NaiveDateTime::from_timestamp_millis(ts_unix).ok_or(anyhow!("Timestamp out of range!"))
}

fn win_reg_str_ts_to_date_time(ts_str: &str) -> Result<NaiveDateTime> {
    Ok(NaiveDateTime::parse_from_str(ts_str, "%m/%d/%Y %H:%M:%S")?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amcache_parsing_works_win10() -> Result<()> {
        let mut parser = Parser::load(&PathBuf::from(
            "/mnt/hgfs/vm_shared/win10_vm_hives/am/Amcache.hve",
        ))?;
        let artifact_map = parser.parse_amcache()?;
        println!("{:#?}", artifact_map);
        Ok(())
    }

    #[test]
    fn shimcache_parsing_works_win7() -> Result<()> {
        let mut parser = Parser::load(&PathBuf::from(
            "/mnt/hgfs/vm_shared/Module 5 - Disk/cache/shimcache/SYSTEM",
        ))?;
        let _shimcache_entries = parser.parse_shimcache()?;
        Ok(())
    }

    #[test]
    fn shimcache_parsing_works_win10() -> Result<()> {
        let mut parser = Parser::load(&PathBuf::from(
            "/mnt/hgfs/vm_shared/win10_vm_hives/shim/SYSTEM",
        ))?;
        let shimcache_entries = parser.parse_shimcache()?;
        for entry in shimcache_entries {
            println!("{entry}");
        }
        Ok(())
    }

}
