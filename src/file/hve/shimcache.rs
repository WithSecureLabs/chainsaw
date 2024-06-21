use std::fmt::Display;

use chrono::{DateTime, Utc};
use serde::Serialize;

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

#[derive(Debug, Serialize)]
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

#[derive(Debug, Serialize)]
pub enum CPUArchitecture {
    Amd64,
    Arm,
    I386,
    Ia64,
    Unknown(u16),
}

impl CPUArchitecture {
    fn from_u16(num: u16) -> CPUArchitecture {
        match num {
            34404 => CPUArchitecture::Amd64,
            452 => CPUArchitecture::Arm,
            332 => CPUArchitecture::I386,
            512 => CPUArchitecture::Ia64,
            num => CPUArchitecture::Unknown(num),
        }
    }
}

#[derive(Debug, Serialize)]
pub enum EntryType {
    File {
        path: String,
    },
    Program {
        raw_entry: String,
        unknown_u32: String,
        architecture: CPUArchitecture,
        program_name: String,
        program_version: String,
        sdk_version: String,
        publisher_id: String,
        neutral: bool,
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
            ShimcacheVersion::Windows7x64Windows2008R2 => {
                write!(f, "Windows 7 64-bit or Windows Server 2008 R2")
            }
            ShimcacheVersion::Windows7x86 => write!(f, "Windows 7 32-bit"),
            ShimcacheVersion::Windows80Windows2012 => write!(f, "Windows 8 or Windows Server 2012"),
            ShimcacheVersion::Windows81Windows2012R2 => write!(f, "Windows 8.1 or Windows 2012 R2"),
            ShimcacheVersion::WindowsVistaWin2k3Win2k8 => write!(
                f,
                "Windows Vista, Windows Server 2003 or Windows Server 2008"
            ),
            ShimcacheVersion::WindowsXP => write!(f, "Unknown"),
        }
    }
}

#[derive(Debug)]
pub struct ShimcacheArtefact {
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
            Some(ts) => write!(
                f,
                "{}:\t{:?}, {}",
                self.cache_entry_position, ts, path_or_name
            ),
            None => write!(f, "{}:\t {}", self.cache_entry_position, path_or_name),
        }
    }
}

impl super::Parser {
    pub fn parse_shimcache(&mut self) -> crate::Result<ShimcacheArtefact> {
        // Find current ControlSet
        let current_controlset_key = self
            .inner
            .get_key("Select", false)?
            .ok_or(anyhow!("Key \"Select\" not found in shimcache!"))?;
        let current_controlset_value = current_controlset_key
            .get_value("Current")
            .ok_or(anyhow!(
                "Value \"Current\" not found under key \"Select\" in shimcache!"
            ))?
            .get_content()
            .0;
        let controlset = match current_controlset_value {
            notatin::cell_value::CellValue::U32(num) => num,
            _ => bail!("Value \"Current\" under key \"Select\" was not of type U32 in shimcache!"),
        };

        // Load shimcache binary data
        let controlset_name = format!("ControlSet{:0>3}", controlset);
        let shimcache_key_path =
            format!("{controlset_name}\\Control\\Session Manager\\AppCompatCache");
        let shimcache_key = self
            .inner
            .get_key(&shimcache_key_path, false)?
            .ok_or(anyhow!(
                "Could not find AppCompatCache with path {}!",
                shimcache_key_path
            ))?;
        let shimcache_last_update_ts = shimcache_key.last_key_written_date_and_time();
        let shimcache_cell_value = shimcache_key
            .get_value("AppCompatCache")
            .ok_or(anyhow!(
                "Value \"AppCompatCache\" not found under key \"{}\"!",
                shimcache_key_path
            ))?
            .get_content()
            .0;
        let shimcache_bytes = match shimcache_cell_value {
            notatin::cell_value::CellValue::Binary(bytes) => bytes,
            _ => bail!("Shimcache value was not of type Binary!"),
        };

        // Find shimcache version
        let e = || anyhow!("Shimcache byte indexing error!");
        let signature_number =
            u32::from_le_bytes(shimcache_bytes.get(0..4).ok_or_else(e)?.try_into()?);

        let shimcache_version: ShimcacheVersion = match signature_number {
            // Windows XP shimcache
            0xdeadbeef => ShimcacheVersion::WindowsXP,
            // Windows Vista shimcache
            0xbadc0ffe => ShimcacheVersion::WindowsVistaWin2k3Win2k8,
            // Windows 7 shimcache
            0xbadc0fee => {
                // Check if system is 32-bit
                let environment_key_path =
                    format!("{controlset_name}\\Control\\Session Manager\\Environment");
                let environment_key =
                    self.inner
                        .get_key(&environment_key_path, false)?
                        .ok_or(anyhow!(
                            "Key \"{environment_key_path}\" not found in shimcache!"
                        ))?;
                let processor_architecture_value = environment_key.get_value("PROCESSOR_ARCHITECTURE")
                .ok_or(anyhow!("Value \"PROCESSOR_ARCHITECTURE\" not found under key \"{environment_key_path}\" in shimcache!"))?.get_content().0;
                let is_32bit = match processor_architecture_value {
                    notatin::cell_value::CellValue::String(s) => s == "x86",
                    _ => bail!("Value \"PROCESSOR_ARCHITECTURE\" under key \"{environment_key_path}\" was not of type String in shimcache!")
                };

                // Windows 7 32-bit
                if is_32bit {
                    ShimcacheVersion::Windows7x86
                }
                // Windows 7 64-bit
                else {
                    ShimcacheVersion::Windows7x64Windows2008R2
                }
            }
            _ => {
                let win8_cache_signature =
                    std::str::from_utf8(shimcache_bytes.get(128..132).ok_or_else(e)?);

                match win8_cache_signature {
                    // Windows 8 shimcache
                    Ok("00ts") => ShimcacheVersion::Windows80Windows2012,
                    // Windows 8.1 shimcache
                    Ok("10ts") => ShimcacheVersion::Windows81Windows2012R2,
                    // Windows 10 shimcache
                    _ => {
                        let offset_to_records = signature_number as usize;
                        let win10_cache_signature = std::str::from_utf8(
                            shimcache_bytes
                                .get(offset_to_records..offset_to_records + 4)
                                .ok_or_else(e)?,
                        );
                        match win10_cache_signature {
                            Ok("10ts") => match offset_to_records {
                                0x34 => ShimcacheVersion::Windows10Creators,
                                _ => ShimcacheVersion::Windows10,
                            },
                            _ => ShimcacheVersion::Unknown,
                        }
                    }
                }
            }
        };

        // Parse shimcache entries
        let shimcache_entries = match shimcache_version {
            ShimcacheVersion::Unknown => {
                bail!("Could not recognize shimcache version!")
            }
            ShimcacheVersion::Windows10 | ShimcacheVersion::Windows10Creators => {
                windows_10_cache::parse(&shimcache_bytes, controlset)
            }
            ShimcacheVersion::Windows7x64Windows2008R2 => {
                windows7x64_windows2008r2_cache::parse(&shimcache_bytes, controlset)
            }
            ShimcacheVersion::Windows7x86 => windows7x86_cache::parse(&shimcache_bytes, controlset),
            ShimcacheVersion::Windows80Windows2012 | ShimcacheVersion::Windows81Windows2012R2 => {
                windows8_cache::parse(&shimcache_bytes, controlset)
            }
            ShimcacheVersion::WindowsVistaWin2k3Win2k8 => {
                windows_vista_win2k3_win2k8_cache::parse(&shimcache_bytes, controlset)
            }
            ShimcacheVersion::WindowsXP => windows_xp_cache::parse(&shimcache_bytes, controlset),
        }
        .map_err(|e| {
            anyhow!(
                "Failed to parse {} shimcache data. Error: {}",
                shimcache_version,
                e
            )
        })?;

        Ok(ShimcacheArtefact {
            entries: shimcache_entries,
            last_update_ts: shimcache_last_update_ts,
            version: shimcache_version,
        })
    }
}

/// Converts a slice of bytes representing UTF-16 into a String
fn utf16_to_string(bytes: &[u8]) -> crate::Result<String> {
    let bytes_vec = Vec::from_iter(bytes);
    let chunk_iterator = bytes_vec.chunks_exact(2);
    if !chunk_iterator.remainder().is_empty() {
        bail!("Bytes did not align to 16 bits!");
    }
    let word_vector: Vec<u16> = chunk_iterator
        .map(|a| u16::from_ne_bytes([*a[0], *a[1]]))
        .collect();
    let word_slice: &[u16] = word_vector.as_slice();
    Ok(String::from_utf16(word_slice)?)
}

mod windows_10_cache {
    use super::{utf16_to_string, CPUArchitecture, EntryType, ShimcacheEntry};

    use lazy_static::lazy_static;
    use regex::Regex;

    use crate::file::win32_ts_to_datetime;

    pub fn parse(shimcache_bytes: &[u8], controlset: u32) -> crate::Result<Vec<ShimcacheEntry>> {
        let mut shimcache_entries: Vec<ShimcacheEntry> = Vec::new();
        let mut index = u32::from_le_bytes(
            shimcache_bytes
                .get(0..4)
                .ok_or(anyhow!("could not get offset to records"))?
                .try_into()?,
        ) as usize;
        let mut cache_entry_position = 0;
        while index < shimcache_bytes.len() {
            let e = || {
                anyhow!(
                    "Error parsing windows 10 shimcache entry. Position: {}",
                    cache_entry_position
                )
            };
            let signature =
                std::str::from_utf8(shimcache_bytes.get(index..index + 4).ok_or_else(e)?)?
                    .to_string();
            if signature != "10ts" {
                break;
            }
            index += 4;
            // skip 4 unknown
            index += 4;
            let _cache_entry_size = u32::from_le_bytes(
                shimcache_bytes
                    .get(index..index + 4)
                    .ok_or_else(e)?
                    .try_into()?,
            );
            index += 4;
            let path_size = u16::from_le_bytes(
                shimcache_bytes
                    .get(index..index + 2)
                    .ok_or_else(e)?
                    .try_into()?,
            ) as usize;
            index += 2;
            let path = utf16_to_string(
                shimcache_bytes
                    .get(index..index + path_size)
                    .ok_or_else(e)?,
            )?;
            index += path_size;
            let last_modified_time_utc_win32 = u64::from_le_bytes(
                shimcache_bytes
                    .get(index..index + 8)
                    .ok_or_else(e)?
                    .try_into()?,
            );
            index += 8;
            let data_size = u32::from_le_bytes(
                shimcache_bytes
                    .get(index..index + 4)
                    .ok_or_else(e)?
                    .try_into()?,
            ) as usize;
            index += 4;
            let data = Some(
                shimcache_bytes
                    .get(index..index + data_size)
                    .ok_or_else(e)?
                    .to_vec(),
            );
            index += data_size;

            // Parse program entries further
            lazy_static! {
                static ref PROGRAM_RE: Regex = Regex::new(
                    r"^([0-9a-f]{8})\s+([0-9a-f]{16})\s+([0-9a-f]{16})\s+([0-9a-f]{4})\s+([\w.-]+)\s+(\w+)\s*(\w*)$"
                ).expect("invalid regex");
            }
            let entry_type: EntryType = if PROGRAM_RE.is_match(&path) {
                fn parse_version_hex(hex_str: &str) -> String {
                    let version_numbers: Result<Vec<u16>, _> = vec![
                        u16::from_str_radix(&hex_str[0..4], 16),
                        u16::from_str_radix(&hex_str[4..8], 16),
                        u16::from_str_radix(&hex_str[8..12], 16),
                        u16::from_str_radix(&hex_str[12..16], 16),
                    ]
                    .into_iter()
                    .collect();
                    version_numbers
                        .map(|numbers| {
                            let number_strings: Vec<String> =
                                numbers.into_iter().map(|n| n.to_string()).collect();
                            number_strings.join(".")
                        })
                        .expect("unable to parse hex strings")
                }
                let capture = PROGRAM_RE
                    .captures(&path)
                    .expect("regex could not capture groups");
                let unknown_u32 = capture
                    .get(1)
                    .expect("could not get group")
                    .as_str()
                    .to_string();
                let program_version =
                    parse_version_hex(capture.get(2).expect("could not get group").as_str());
                let sdk_version =
                    parse_version_hex(capture.get(3).expect("could not get group").as_str());
                let architecture_u16 =
                    u16::from_str_radix(capture.get(4).expect("could not get group").as_str(), 16)
                        .expect("could not parse hex string");
                let architecture = CPUArchitecture::from_u16(architecture_u16);
                let program_name = capture
                    .get(5)
                    .expect("could not get group")
                    .as_str()
                    .to_string();
                let publisher_id = capture
                    .get(6)
                    .expect("could not get group")
                    .as_str()
                    .to_string();
                let neutral = capture.get(7).expect("could not get group").as_str() == "neutral";

                EntryType::Program {
                    program_name,
                    raw_entry: path,
                    unknown_u32,
                    program_version,
                    architecture,
                    sdk_version,
                    publisher_id,
                    neutral,
                }
            } else {
                EntryType::File { path }
            };
            let last_modified_ts = if last_modified_time_utc_win32 != 0 {
                let last_modified_date_time = win32_ts_to_datetime(last_modified_time_utc_win32)?;
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

            shimcache_entries.push(cache_entry);
            cache_entry_position += 1;
        }
        Ok(shimcache_entries)
    }
}

mod windows7x64_windows2008r2_cache {
    use super::{utf16_to_string, EntryType, InsertFlag, ShimcacheEntry};

    use crate::file::win32_ts_to_datetime;

    pub fn parse(shimcache_bytes: &[u8], controlset: u32) -> crate::Result<Vec<ShimcacheEntry>> {
        let mut shimcache_entries: Vec<ShimcacheEntry> = Vec::new();
        let mut index = 4;
        let entry_count = u32::from_le_bytes(
            shimcache_bytes
                .get(index..index + 4)
                .expect("could not index shimcache bytes")
                .try_into()?,
        ) as usize;
        if entry_count == 0 {
            return Ok(shimcache_entries);
        }
        index = 128;
        let mut cache_entry_position = 0;
        while index < shimcache_bytes.len() {
            let e = || {
                anyhow!(
                    "Error parsing windows 7 shimcache entry. Position: {}",
                    cache_entry_position
                )
            };
            let path_size = u16::from_le_bytes(
                shimcache_bytes
                    .get(index..index + 2)
                    .ok_or_else(e)?
                    .try_into()?,
            ) as usize;
            index += 2;
            let _max_path_size = u16::from_le_bytes(
                shimcache_bytes
                    .get(index..index + 2)
                    .ok_or_else(e)?
                    .try_into()?,
            ) as usize;
            index += 2;
            // skip 4 unknown (padding)
            index += 4;
            let path_offset = u64::from_le_bytes(
                shimcache_bytes
                    .get(index..index + 8)
                    .ok_or_else(e)?
                    .try_into()?,
            ) as usize;
            index += 8;
            let last_modified_time_utc_win32 = u64::from_le_bytes(
                shimcache_bytes
                    .get(index..index + 8)
                    .ok_or_else(e)?
                    .try_into()?,
            );
            index += 8;
            let insert_flags = u32::from_le_bytes(
                shimcache_bytes
                    .get(index..index + 4)
                    .ok_or_else(e)?
                    .try_into()?,
            );
            index += 4;
            // skip 4 (shim flags)
            index += 4;
            let data_size = u64::from_le_bytes(
                shimcache_bytes
                    .get(index..index + 8)
                    .ok_or_else(e)?
                    .try_into()?,
            ) as usize;
            index += 8;
            let data_offset = u64::from_le_bytes(
                shimcache_bytes
                    .get(index..index + 8)
                    .ok_or_else(e)?
                    .try_into()?,
            ) as usize;
            index += 8;

            let path = utf16_to_string(
                shimcache_bytes
                    .get(path_offset..path_offset + path_size)
                    .ok_or_else(e)?,
            )?
            .replace(r"\??\", "");
            let data = Some(
                shimcache_bytes
                    .get(data_offset..data_offset + data_size)
                    .ok_or_else(e)?
                    .to_vec(),
            );
            let last_modified_ts = if last_modified_time_utc_win32 != 0 {
                let last_modified_date_time = win32_ts_to_datetime(last_modified_time_utc_win32)?;
                Some(last_modified_date_time)
            } else {
                None
            };
            let executed =
                Some(insert_flags & InsertFlag::Executed as u32 == InsertFlag::Executed as u32);
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

            shimcache_entries.push(cache_entry);
            if shimcache_entries.len() >= entry_count {
                break;
            }
            cache_entry_position += 1;
        }
        Ok(shimcache_entries)
    }
}

mod windows7x86_cache {
    use super::{utf16_to_string, EntryType, InsertFlag, ShimcacheEntry};

    use crate::file::win32_ts_to_datetime;

    pub fn parse(shimcache_bytes: &[u8], controlset: u32) -> crate::Result<Vec<ShimcacheEntry>> {
        let mut shimcache_entries: Vec<ShimcacheEntry> = Vec::new();
        let mut index = 4;
        let entry_count = u32::from_le_bytes(
            shimcache_bytes
                .get(index..index + 4)
                .expect("could not index shimcache bytes")
                .try_into()?,
        ) as usize;
        if entry_count == 0 {
            return Ok(shimcache_entries);
        }
        index = 128;
        let mut cache_entry_position = 0;
        while index < shimcache_bytes.len() {
            let e = || {
                anyhow!(
                    "Error parsing windows 7 shimcache entry. Position: {}",
                    cache_entry_position
                )
            };
            let path_size = u16::from_le_bytes(
                shimcache_bytes
                    .get(index..index + 2)
                    .ok_or_else(e)?
                    .try_into()?,
            ) as usize;
            index += 2;
            let _max_path_size = u16::from_le_bytes(
                shimcache_bytes
                    .get(index..index + 2)
                    .ok_or_else(e)?
                    .try_into()?,
            ) as usize;
            index += 2;
            let path_offset = u32::from_le_bytes(
                shimcache_bytes
                    .get(index..index + 4)
                    .ok_or_else(e)?
                    .try_into()?,
            ) as usize;
            index += 4;
            let last_modified_time_utc_win32 = u64::from_le_bytes(
                shimcache_bytes
                    .get(index..index + 8)
                    .ok_or_else(e)?
                    .try_into()?,
            );
            index += 8;
            let insert_flags = u32::from_le_bytes(
                shimcache_bytes
                    .get(index..index + 4)
                    .ok_or_else(e)?
                    .try_into()?,
            );
            index += 4;
            // skip 4 (shim flags)
            index += 4;
            let data_size = u32::from_le_bytes(
                shimcache_bytes
                    .get(index..index + 4)
                    .ok_or_else(e)?
                    .try_into()?,
            ) as usize;
            index += 4;
            let data_offset = u32::from_le_bytes(
                shimcache_bytes
                    .get(index..index + 4)
                    .ok_or_else(e)?
                    .try_into()?,
            ) as usize;
            index += 4;

            let path = utf16_to_string(
                shimcache_bytes
                    .get(path_offset..path_offset + path_size)
                    .ok_or_else(e)?,
            )?
            .replace(r"\??\", "");
            let data = Some(
                shimcache_bytes
                    .get(data_offset..data_offset + data_size)
                    .ok_or_else(e)?
                    .to_vec(),
            );
            let last_modified_ts = if last_modified_time_utc_win32 != 0 {
                let last_modified_date_time = win32_ts_to_datetime(last_modified_time_utc_win32)?;
                Some(last_modified_date_time)
            } else {
                None
            };
            let executed =
                Some(insert_flags & InsertFlag::Executed as u32 == InsertFlag::Executed as u32);
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

            shimcache_entries.push(cache_entry);
            if shimcache_entries.len() >= entry_count {
                break;
            }
            cache_entry_position += 1;
        }
        Ok(shimcache_entries)
    }
}

mod windows8_cache {
    use super::{utf16_to_string, EntryType, InsertFlag, ShimcacheEntry};

    use crate::file::win32_ts_to_datetime;

    pub fn parse(shimcache_bytes: &[u8], controlset: u32) -> crate::Result<Vec<ShimcacheEntry>> {
        let mut shimcache_entries: Vec<ShimcacheEntry> = Vec::new();
        let e = || anyhow!("Shimcache byte indexing error!");
        let cache_signature = std::str::from_utf8(shimcache_bytes.get(128..132).ok_or_else(e)?)?;
        if !(cache_signature == "00ts" || cache_signature == "10ts") {
            panic!("not a valid Windows 8 shimcache signature!");
        }
        let mut index = 128;
        let mut cache_entry_position = 0;
        while index < shimcache_bytes.len() {
            let signature =
                std::str::from_utf8(shimcache_bytes.get(index..index + 4).ok_or_else(e)?)?
                    .to_string();
            if signature != cache_signature {
                break;
            }
            index += 4;
            // skip 4 unknown
            index += 4;
            let _ce_data_size = u32::from_le_bytes(
                shimcache_bytes
                    .get(index..index + 4)
                    .ok_or_else(e)?
                    .try_into()?,
            ) as usize;
            index += 4;
            let path_size = u16::from_le_bytes(
                shimcache_bytes
                    .get(index..index + 2)
                    .ok_or_else(e)?
                    .try_into()?,
            ) as usize;
            index += 2;
            let mut path = utf16_to_string(
                shimcache_bytes
                    .get(index..index + path_size)
                    .ok_or_else(e)?,
            )?;
            index += path_size;
            let package_len = u16::from_le_bytes(
                shimcache_bytes
                    .get(index..index + 2)
                    .ok_or_else(e)?
                    .try_into()?,
            ) as usize;
            index += 2;
            //skip package data
            index += package_len;
            let insert_flags = u32::from_le_bytes(
                shimcache_bytes
                    .get(index..index + 4)
                    .ok_or_else(e)?
                    .try_into()?,
            );
            index += 4;
            // skip 4 (shim flags)
            index += 4;
            let last_modified_time_utc_win32 = u64::from_le_bytes(
                shimcache_bytes
                    .get(index..index + 8)
                    .ok_or_else(e)?
                    .try_into()?,
            );
            index += 8;
            let data_size = u32::from_le_bytes(
                shimcache_bytes
                    .get(index..index + 4)
                    .ok_or_else(e)?
                    .try_into()?,
            ) as usize;
            index += 4;
            let data = Some(
                shimcache_bytes
                    .get(index..index + data_size)
                    .ok_or_else(e)?
                    .to_vec(),
            );
            index += data_size;

            // TODO: find a way to avoid below assumption
            // Assume "SYSVOL\" refers to "C:\"
            if path.starts_with(r"SYSVOL\") {
                path = path.replacen(r"SYSVOL\", r"C:\", 1);
            }
            let entry_type = EntryType::File { path };
            let executed =
                Some(insert_flags & InsertFlag::Executed as u32 == InsertFlag::Executed as u32);
            let last_modified_ts = if last_modified_time_utc_win32 != 0 {
                let last_modified_date_time = win32_ts_to_datetime(last_modified_time_utc_win32)?;
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

            shimcache_entries.push(cache_entry);
            cache_entry_position += 1;
        }
        Ok(shimcache_entries)
    }
}

mod windows_vista_win2k3_win2k8_cache {
    use super::ShimcacheEntry;

    pub fn parse(_shimcache_bytes: &[u8], _controlset: u32) -> crate::Result<Vec<ShimcacheEntry>> {
        bail!("Windows Vista shimcache parsing not supported!");
    }
}

mod windows_xp_cache {
    use super::ShimcacheEntry;

    pub fn parse(_shimcache_bytes: &[u8], _controlset: u32) -> crate::Result<Vec<ShimcacheEntry>> {
        bail!("Windows XP shimcache parsing not supported!");
    }
}
