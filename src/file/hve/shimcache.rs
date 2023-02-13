use std::{fmt::Display};

use anyhow::{Result, bail, anyhow};
use chrono::{NaiveDateTime, DateTime, Utc};
use lazy_static::lazy_static;
use regex::Regex;

#[allow(dead_code)]
enum InsertFlag {
    Unknown1 = 0x00000001,
    Executed = 0x00000002,
    Unknown4 = 0x00000004,
    Unknown8 = 0x00000008,
    Unknown10 = 0x00000010,
    Unknown20 = 0x00000020,
    Unknown40 = 0x00000040,
    Unknown80 = 0x00000080,
    Unknown10000 = 0x00010000,
    Unknown20000 = 0x00020000,
    Unknown30000 = 0x00030000,
    Unknown40000 = 0x00040000,
    Unknown100000 = 0x00100000,
    Unknown200000 = 0x00200000,
    Unknown400000 = 0x00400000,
    Unknown800000 = 0x00800000,
}

#[derive(Debug)]
pub struct ShimCacheEntry {
    pub signature: Option<String>,
    pub path_size: usize,
    pub program: ProgramType,
    pub last_modified_ts: Option<DateTime<Utc>>,
    pub data_size: Option<usize>,
    pub data: Option<Vec<u8>>,
    pub executed: Option<bool>,
    pub controlset: u32,
    pub cache_entry_position: u32,
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

impl super::Parser {
    pub fn parse_shimcache (&mut self) -> Result<Vec<ShimCacheEntry>> {
        // Find current ControlSet
        let current_controlset_key = self.inner.get_key("Select", false)?
            .ok_or(anyhow!("Key \"Select\" not found in shimcache!"))?;
        let current_controlset_value = current_controlset_key.get_value("Current")
            .ok_or(anyhow!("Value \"Current\" not found under key \"Select\" in shimcache!"))?.get_content().0;
        let controlset = match current_controlset_value {
            notatin::cell_value::CellValue::U32(num) => num,
            _ => bail!("Value \"Current\" under key \"Select\" was not of type U32 in shimcache!")
        };

        // Load shimcache binary data
        let controlset_name = format!("ControlSet{:0>3}", controlset);
        let shimcache_key_path = format!("{controlset_name}\\Control\\Session Manager\\AppCompatCache");
        let shimcache_key = self
            .inner
            .get_key(&shimcache_key_path, false)?
            .ok_or(anyhow!("Could not find AppCompatCache with path {}!", shimcache_key_path))?;
        let shimcache_cell_value = shimcache_key.get_value("AppCompatCache")
            .ok_or(anyhow!("Value \"AppCompatCache\" not found under key \"{}\"!", shimcache_key_path))?
            .get_content().0;
        let shimcache_bytes = match shimcache_cell_value {
            notatin::cell_value::CellValue::Binary(bytes) => bytes,
            _ => bail!("Shimcache value was not of type Binary!"),
        };
        let shimcache_len = shimcache_bytes.len();

        let mut shimcache_entries: Vec<ShimCacheEntry> = Vec::new();

        // Shimcache version signature is at a different index depending on version
        let e = || anyhow!("Shimcache byte indexing error!");
        let signature_number = u32::from_le_bytes(shimcache_bytes.get(0..4).ok_or_else(e)?.try_into()?);
        let cache_signature = std::str::from_utf8(&shimcache_bytes.get(128..132).ok_or_else(e)?)?;

        // Windows XP shimcache
        if signature_number == 0xdeadbeef {
            bail!("Windows XP shimcache parsing not supported!");
        }
        // Windows Vista shimcache
        else if signature_number == 0xbadc0ffe
        {
            bail!("Windows Vista shimcache parsing not supported!");
        }
        // Windows 7 shimcache
        else if signature_number == 0xbadc0fee {
            // Check if system is 32-bit
            let environment_key_path = format!("{controlset_name}\\Control\\Session Manager\\Environment");
            let environment_key = self.inner.get_key(&environment_key_path, false)?
                .ok_or(anyhow!("Key \"{environment_key_path}\" not found in shimcache!"))?;
            let processor_architecture_value = environment_key.get_value("PROCESSOR_ARCHITECTURE")
                .ok_or(anyhow!("Value \"PROCESSOR_ARCHITECTURE\" not found under key \"{environment_key_path}\" in shimcache!"))?.get_content().0;
            let is_32bit = match processor_architecture_value {
                notatin::cell_value::CellValue::String(s) => s == "x86",
                _ => bail!("Value \"PROCESSOR_ARCHITECTURE\" under key \"{environment_key_path}\" was not of type String in shimcache!")
            };
            let mut index = 4;
            let entry_count = u32::from_le_bytes(shimcache_bytes.get(index..index+4).expect("could not index shimcache bytes").try_into()?) as usize;
            if entry_count == 0 {
                return Ok(shimcache_entries);
            }
            index = 128;
            let mut cache_entry_position = 0;

            if is_32bit {
                // TODO: verify that 32-bit win7 parsing works properly
                while index < shimcache_len {
                    let e = || anyhow!("Error parsing windows 7 shimcache entry. Position: {}", cache_entry_position);
                    let path_size = u16::from_le_bytes(shimcache_bytes.get(index..index+2).ok_or_else(e)?.try_into()?) as usize;
                    index += 2;
                    let _max_path_size = u16::from_le_bytes(shimcache_bytes.get(index..index+2).ok_or_else(e)?.try_into()?) as usize;
                    index += 2;
                    let path_offset = u32::from_le_bytes(shimcache_bytes.get(index..index+4).ok_or_else(e)?.try_into()?) as usize;
                    index += 4;
                    let last_modified_time_utc_win32 = u64::from_le_bytes(shimcache_bytes.get(index..index+8).ok_or_else(e)?.try_into()?);
                    index += 8;
                    let insert_flags = u32::from_le_bytes(shimcache_bytes.get(index..index+4).ok_or_else(e)?.try_into()?);
                    index += 4;
                    // skip 4 (shim flags)
                    index += 4;
                    let data_size = u32::from_le_bytes(shimcache_bytes.get(index..index+4).ok_or_else(e)?.try_into()?) as usize;
                    index += 4;
                    let data_offset = u32::from_le_bytes(shimcache_bytes.get(index..index+4).ok_or_else(e)?.try_into()?) as usize;
                    index += 4;

                    let path = utf16_to_string(&shimcache_bytes.get(path_offset..path_offset+path_size).ok_or_else(e)?)?.replace(r"\??\", "");
                    let data = Some(shimcache_bytes.get(data_offset..data_offset+data_size).ok_or_else(e)?.to_vec());
                    let last_modified_ts = if last_modified_time_utc_win32 != 0 {
                        let last_modified_time_utc = win32_ts_to_datetime(last_modified_time_utc_win32)?;
                        let last_modified_date_time = DateTime::<Utc>::from_utc(last_modified_time_utc, Utc);
                        Some(last_modified_date_time)
                    } else {
                        None
                    };
                    let executed = Some(insert_flags & InsertFlag::Executed as u32 == InsertFlag::Executed as u32);
                    let program = ProgramType::Executable { path };
    
                    let cache_entry = ShimCacheEntry {
                        cache_entry_position,
                        data,
                        data_size: Some(data_size),
                        executed,
                        last_modified_ts,
                        program,
                        path_size,
                        signature: None,
                        controlset,
                    };
    
                    shimcache_entries.push(cache_entry);
                    if shimcache_entries.len() >= entry_count {
                        break;
                    }
                    cache_entry_position += 1;
                }
            } else {
                while index < shimcache_len {
                    let e = || anyhow!("Error parsing windows 7 shimcache entry. Position: {}", cache_entry_position);
                    let path_size = u16::from_le_bytes(shimcache_bytes.get(index..index+2).ok_or_else(e)?.try_into()?) as usize;
                    index += 2;
                    let _max_path_size = u16::from_le_bytes(shimcache_bytes.get(index..index+2).ok_or_else(e)?.try_into()?) as usize;
                    index += 2;
                    // skip 4 unknown (padding)
                    index += 4;
                    let path_offset = u64::from_le_bytes(shimcache_bytes.get(index..index+8).ok_or_else(e)?.try_into()?) as usize;
                    index += 8;
                    let last_modified_time_utc_win32 = u64::from_le_bytes(shimcache_bytes.get(index..index+8).ok_or_else(e)?.try_into()?);
                    index += 8;
                    let insert_flags = u32::from_le_bytes(shimcache_bytes.get(index..index+4).ok_or_else(e)?.try_into()?);
                    index += 4;
                    // skip 4 (shim flags)
                    index += 4;
                    let data_size = u64::from_le_bytes(shimcache_bytes.get(index..index+8).ok_or_else(e)?.try_into()?) as usize;
                    index += 8;
                    let data_offset = u64::from_le_bytes(shimcache_bytes.get(index..index+8).ok_or_else(e)?.try_into()?) as usize;
                    index += 8;

                    let path = utf16_to_string(&shimcache_bytes.get(path_offset..path_offset+path_size).ok_or_else(e)?)?.replace(r"\??\", "");
                    let data = Some(shimcache_bytes.get(data_offset..data_offset+data_size).ok_or_else(e)?.to_vec());
                    let last_modified_ts = if last_modified_time_utc_win32 != 0 {
                        let last_modified_time_utc = win32_ts_to_datetime(last_modified_time_utc_win32)?;
                        let last_modified_date_time = DateTime::<Utc>::from_utc(last_modified_time_utc, Utc);
                        Some(last_modified_date_time)
                    } else {
                        None
                    };
                    let executed = Some(insert_flags & InsertFlag::Executed as u32 == InsertFlag::Executed as u32);
                    let program = ProgramType::Executable { path };
    
                    let cache_entry = ShimCacheEntry {
                        cache_entry_position,
                        data,
                        data_size: Some(data_size),
                        executed,
                        last_modified_ts,
                        program,
                        path_size,
                        signature: None,
                        controlset,
                    };
    
                    shimcache_entries.push(cache_entry);
                    if shimcache_entries.len() >= entry_count {
                        break;
                    }
                    cache_entry_position += 1;
                }
            }
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
            let offset_to_records = signature_number.clone() as usize;
            let cache_signature = std::str::from_utf8(&shimcache_bytes.get(offset_to_records..offset_to_records+4).ok_or_else(e)?)?;
            // Windows 10 shimcache
            if cache_signature == "10ts" {
                lazy_static! {
                    static ref RE: Regex = Regex::new(
                        r"^([0-9a-f]{8})\s+([0-9a-f]{16})\s+([0-9a-f]{16})\s+([\w]{4})\s+([\w.]+)\s+(\w+)\s*(\w*)$"
                    ).expect("invalid regex");
                }
                let mut index = offset_to_records.clone();
                let mut cache_entry_position = 0;
                while index < shimcache_len {
                    let e = || anyhow!("Error parsing windows 10 shimcache entry. Position: {}", cache_entry_position);
                    let signature = std::str::from_utf8(&shimcache_bytes.get(index..index+4).ok_or_else(e)?)?.to_string();
                    if signature != "10ts" {
                        break;
                    }
                    index += 4;
                    // skip 4 unknown
                    index += 4;
                    let _cache_entry_size = u32::from_le_bytes(shimcache_bytes.get(index..index+4).ok_or_else(e)?.try_into()?);
                    index += 4;
                    let path_size = u16::from_le_bytes(shimcache_bytes.get(index..index+2).ok_or_else(e)?.try_into()?) as usize;
                    index += 2;
                    let path = utf16_to_string(&shimcache_bytes.get(index..index+path_size).ok_or_else(e)?)?;
                    let program: ProgramType;
                    if RE.is_match(&path) {
                        let program_name = RE.captures(&path).expect("regex could not capture groups")
                            .get(5).expect("could not get group 5 of regex")
                            .as_str().to_string();
                        program = ProgramType::Program { program_name, full_string: path };
                    } else {
                        program = ProgramType::Executable { path };
                    }
                    index += path_size;
                    let last_modified_time_utc_win32 = u64::from_le_bytes(shimcache_bytes.get(index..index+8).ok_or_else(e)?.try_into()?);
                    index += 8;
                    let data_size = u32::from_le_bytes(shimcache_bytes.get(index..index+4).ok_or_else(e)?.try_into()?) as usize;
                    index += 4;
                    let data = Some(shimcache_bytes.get(index..index+data_size).ok_or_else(e)?.to_vec());
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
                        data_size: Some(data_size),
                        executed: None,
                        last_modified_ts,
                        program,
                        path_size,
                        signature: Some(signature),
                        controlset,
                    };

                    shimcache_entries.push(cache_entry);
                    cache_entry_position += 1;
                }
            }
        }

        Ok(shimcache_entries)
    }
}

fn win32_ts_to_datetime(ts_win32: u64) -> Result<NaiveDateTime> {
    let ts_unix = (ts_win32 / 10_000) as i64 - 11644473600000;
    NaiveDateTime::from_timestamp_millis(ts_unix).ok_or(anyhow!("Timestamp out of range!"))
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