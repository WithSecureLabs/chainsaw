use std::{fmt::Display};

use anyhow::{Result, bail, anyhow};
use chrono::{DateTime, Utc};
use lazy_static::lazy_static;
use regex::Regex;

use super::win32_ts_to_datetime;

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
pub struct ShimcacheEntry {
    pub cache_entry_position: u32,
    pub controlset: u32,
    pub data_size: Option<usize>,
    pub data: Option<Vec<u8>>,
    pub entry_type: EntryType,
    pub executed: Option<bool>,
    pub last_modified_ts: Option<DateTime<Utc>>,
    pub path_size: usize,
    pub signature: Option<String>,
}

#[derive(Debug)]
pub enum EntryType {
    File {
        path: String
    },
    Program {
        full_string: String,
        program_name: String,
    },
}

#[derive(Debug)]
pub enum ShimcacheVersion {
    Unknown,
    Windows10,
    Windows10Creators,
    Windows7x64Windows2008R2,
    Windows7x86,
    Windows80Windows2012,
    Windows81Windows2012R2,
    WindowsVistaWin2k3Win2k8,
    WindowsXP,
}

impl std::fmt::Display for ShimcacheVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            ShimcacheVersion::Unknown => write!(f, "Unknown"),
            ShimcacheVersion::Windows10 => write!(f, "Windows 10"),
            ShimcacheVersion::Windows10Creators => write!(f, "Windows 10 Creators"),
            ShimcacheVersion::Windows7x64Windows2008R2 => write!(f, "Windows 7 64-bit or Windows Server 2008 R2"),
            ShimcacheVersion::Windows7x86 => write!(f, "Windows 7 32-bit"),
            ShimcacheVersion::Windows80Windows2012 => write!(f, "Windows 8 or Windows Server 2012"),
            ShimcacheVersion::Windows81Windows2012R2 => write!(f, "Windows 8.1 or Windows 2012 R2"),
            ShimcacheVersion::WindowsVistaWin2k3Win2k8 => write!(f, "Windows Vista, Windows Server 2003 or Windows Server 2008"),
            ShimcacheVersion::WindowsXP => write!(f, "Unknown"),
        }
    }
}

#[derive(Debug)]
pub struct ShimcacheArtifact {
    pub entries: Vec<ShimcacheEntry>,
    pub last_update_ts: DateTime<Utc>,
    pub version: ShimcacheVersion,
}

impl Display for ShimcacheEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let path_or_name = match &self.entry_type {
            EntryType::File { path } => path,
            EntryType::Program { program_name, .. } => program_name,
        };
        match self.last_modified_ts {
            Some(ts) => write!(f, "{}:\t{:?}, {}", self.cache_entry_position, ts, path_or_name),
            None => write!(f, "{}:\t {}", self.cache_entry_position, path_or_name),
        }
    }
}

impl super::Parser {
    pub fn parse_shimcache (&mut self) -> Result<ShimcacheArtifact> {
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
        let shimcache_last_update_ts = shimcache_key.last_key_written_date_and_time();
        let shimcache_cell_value = shimcache_key.get_value("AppCompatCache")
            .ok_or(anyhow!("Value \"AppCompatCache\" not found under key \"{}\"!", shimcache_key_path))?
            .get_content().0;
        let shimcache_bytes = match shimcache_cell_value {
            notatin::cell_value::CellValue::Binary(bytes) => bytes,
            _ => bail!("Shimcache value was not of type Binary!"),
        };
        let shimcache_bytes_len = shimcache_bytes.len();

        let mut shimcache = ShimcacheArtifact{
            entries: Vec::new(),
            last_update_ts: shimcache_last_update_ts,
            version: ShimcacheVersion::Unknown,
        };

        // Shimcache version signature is at a different index depending on version
        let e = || anyhow!("Shimcache byte indexing error!");
        let signature_number = u32::from_le_bytes(shimcache_bytes.get(0..4).ok_or_else(e)?.try_into()?);
        let win8_cache_signature = match std::str::from_utf8(&shimcache_bytes.get(128..132).ok_or_else(e)?) {
            Ok(signature) => if signature == "00ts" || signature == "10ts" { Some(signature) } else { None },
            Err(_e) => None,
        };

        // Windows XP shimcache
        if signature_number == 0xdeadbeef {
            shimcache.version = ShimcacheVersion::WindowsXP;
            bail!("Windows XP shimcache parsing not supported!");
        }
        // Windows Vista shimcache
        else if signature_number == 0xbadc0ffe
        {
            shimcache.version = ShimcacheVersion::WindowsVistaWin2k3Win2k8;
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
                return Ok(shimcache);
            }
            index = 128;
            let mut cache_entry_position = 0;

            // Windows 7 32-bit
            if is_32bit {
                shimcache.version = ShimcacheVersion::Windows7x86;
                while index < shimcache_bytes_len {
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
                    let entry_type = EntryType::File { path };
    
                    let cache_entry = ShimcacheEntry {
                        cache_entry_position,
                        data,
                        data_size: Some(data_size),
                        executed,
                        last_modified_ts,
                        entry_type,
                        path_size,
                        signature: None,
                        controlset,
                    };
    
                    shimcache.entries.push(cache_entry);
                    if shimcache.entries.len() >= entry_count {
                        break;
                    }
                    cache_entry_position += 1;
                }
            // Windows 7 64-bit
            } else {
                shimcache.version = ShimcacheVersion::Windows7x64Windows2008R2;
                while index < shimcache_bytes_len {
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
                    let entry_type = EntryType::File { path };
    
                    let cache_entry = ShimcacheEntry {
                        cache_entry_position,
                        data,
                        data_size: Some(data_size),
                        executed,
                        last_modified_ts,
                        entry_type,
                        path_size,
                        signature: None,
                        controlset,
                    };
    
                    shimcache.entries.push(cache_entry);
                    if shimcache.entries.len() >= entry_count {
                        break;
                    }
                    cache_entry_position += 1;
                }
            }
        }
        // Windows 8 or Windows 8.1 shimcache
        else if let Some(cache_signature) = win8_cache_signature {
            if cache_signature == "00ts" {
                shimcache.version = ShimcacheVersion::Windows80Windows2012;
            } else if cache_signature == "10ts" {
                shimcache.version = ShimcacheVersion::Windows81Windows2012R2;
            }
            let mut index = 128;
            let mut cache_entry_position = 0;
            while index < shimcache_bytes_len {
                let signature = std::str::from_utf8(&shimcache_bytes.get(index..index+4).ok_or_else(e)?)?.to_string();
                if signature != cache_signature {
                    break;
                }
                index += 4;
                // skip 4 unknown
                index += 4;
                let _ce_data_size = u32::from_le_bytes(shimcache_bytes.get(index..index+4).ok_or_else(e)?.try_into()?) as usize;
                index += 4;
                let path_size = u16::from_le_bytes(shimcache_bytes.get(index..index+2).ok_or_else(e)?.try_into()?) as usize;
                index += 2;
                let path = utf16_to_string(&shimcache_bytes.get(index..index+path_size).ok_or_else(e)?)?;
                index += path_size;
                let package_len = u16::from_le_bytes(shimcache_bytes.get(index..index+2).ok_or_else(e)?.try_into()?) as usize;
                index += 2;
                //skip package data
                index += package_len;
                let insert_flags = u32::from_le_bytes(shimcache_bytes.get(index..index+4).ok_or_else(e)?.try_into()?);
                index += 4;
                // skip 4 (shim flags)
                index += 4;
                let last_modified_time_utc_win32 = u64::from_le_bytes(shimcache_bytes.get(index..index+8).ok_or_else(e)?.try_into()?);
                index += 8;
                let data_size = u32::from_le_bytes(shimcache_bytes.get(index..index+4).ok_or_else(e)?.try_into()?) as usize;
                index += 4;
                let data = Some(shimcache_bytes.get(index..index+data_size).ok_or_else(e)?.to_vec());
                index += data_size;

                let entry_type = EntryType::File { path };
                let executed = Some(insert_flags & InsertFlag::Executed as u32 == InsertFlag::Executed as u32);
                let last_modified_ts = if last_modified_time_utc_win32 != 0 {
                    let last_modified_time_utc = win32_ts_to_datetime(last_modified_time_utc_win32)?;
                    let last_modified_date_time = DateTime::<Utc>::from_utc(last_modified_time_utc, Utc);
                    Some(last_modified_date_time)
                } else {
                    None
                };

                let cache_entry = ShimcacheEntry {
                    cache_entry_position,
                    data,
                    data_size: Some(data_size),
                    executed,
                    last_modified_ts,
                    entry_type,
                    path_size,
                    signature: Some(signature),
                    controlset,
                };

                shimcache.entries.push(cache_entry);
                cache_entry_position += 1;
            }
        }
        // Windows 10 shimcache
        else {
            let offset_to_records = signature_number.clone() as usize;
            let win10_cache_signature: bool = match std::str::from_utf8(&shimcache_bytes.get(offset_to_records..offset_to_records+4).ok_or_else(e)?) {
                Ok(signature) => signature == "10ts",
                _ => false,
            };
            if offset_to_records == 0x34 {
                shimcache.version = ShimcacheVersion::Windows10Creators;
            } else {
                shimcache.version = ShimcacheVersion::Windows10;
            }
            if win10_cache_signature {
                lazy_static! {
                    static ref RE: Regex = Regex::new(
                        r"^([0-9a-f]{8})\s+([0-9a-f]{16})\s+([0-9a-f]{16})\s+([\w]{4})\s+([\w.]+)\s+(\w+)\s*(\w*)$"
                    ).expect("invalid regex");
                }
                let mut index = offset_to_records.clone();
                let mut cache_entry_position = 0;
                while index < shimcache_bytes_len {
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
                    index += path_size;
                    let last_modified_time_utc_win32 = u64::from_le_bytes(shimcache_bytes.get(index..index+8).ok_or_else(e)?.try_into()?);
                    index += 8;
                    let data_size = u32::from_le_bytes(shimcache_bytes.get(index..index+4).ok_or_else(e)?.try_into()?) as usize;
                    index += 4;
                    let data = Some(shimcache_bytes.get(index..index+data_size).ok_or_else(e)?.to_vec());
                    index += data_size;

                    let entry_type: EntryType;
                    if RE.is_match(&path) {
                        let program_name = RE.captures(&path).expect("regex could not capture groups")
                            .get(5).expect("could not get group 5 of regex")
                            .as_str().to_string();
                        entry_type = EntryType::Program { program_name, full_string: path };
                    } else {
                        entry_type = EntryType::File { path };
                    }
                    let last_modified_ts = if last_modified_time_utc_win32 != 0 {
                        let last_modified_time_utc = win32_ts_to_datetime(last_modified_time_utc_win32)?;
                        let last_modified_date_time = DateTime::<Utc>::from_utc(last_modified_time_utc, Utc);
                        Some(last_modified_date_time)
                    } else {
                        None
                    };

                    let cache_entry = ShimcacheEntry {
                        cache_entry_position,
                        data,
                        data_size: Some(data_size),
                        executed: None,
                        last_modified_ts,
                        entry_type,
                        path_size,
                        signature: Some(signature),
                        controlset,
                    };

                    shimcache.entries.push(cache_entry);
                    cache_entry_position += 1;
                }
            } else {
                bail!("Could not recognize shimcache version!");
            }
        }

        Ok(shimcache)
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