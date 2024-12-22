// The SRUM (System Resource Usage Monitor) is a mechanism first introduced on Windows 8 (2015) that tracks
// programs, services, Windows apps and network connectivity. It relies on extensions/providers and parameters
// defined in HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\ to retrieve data from the system.
// The information is stored in a ESE database, located by default at %SystemRoot%\System32\sru\SRUDB.dat.

// The SRUM parser will analyse the SRUM database and provide insights
use std::collections::BTreeMap;
use std::{fs, path::PathBuf};

use anyhow::{Context, Error};
use chrono::{DateTime, SecondsFormat, Utc};
use prettytable::{Cell, Row, Table};
use serde_json::json;
use serde_json::Value as Json;

use crate::file::esedb::Parser as EsedbParser;
use crate::file::hve::{srum::SrumRegInfo, Parser as HveParser};
use crate::file::win32_ts_to_datetime;

#[derive(Debug)]
struct TableDetails {
    table_name: String,
    dll_path: Option<String>,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
    retention_time_days: Option<f64>,
}

pub struct SrumDbInfo {
    pub table_details: Table,
    pub db_content: Json,
}

pub struct SrumAnalyser {
    srum_path: PathBuf,
    software_hive_path: PathBuf,
}

/// Convert a hex string to an SID string
pub fn bytes_to_sid_string(hex: &[u8]) -> Option<String> {
    const HEADER: &str = "S";

    if hex.is_empty() || hex.len() <= 8 {
        return None;
    }

    let sid_version = hex[0].to_string();
    let auth_id = i32::from_le_bytes([hex[7], hex[6], hex[5], hex[4]]);
    let mut sid = format!("{}-{}-{}", HEADER, sid_version, auth_id);

    for i in (8..hex.len()).step_by(4) {
        let temp_auth_hex = &hex[i..i + 4];
        let temp_auth_hex_string = format!(
            "{:02X?}{:02X?}{:02X?}{:02X?}",
            temp_auth_hex[3], temp_auth_hex[2], temp_auth_hex[1], temp_auth_hex[0]
        );
        if let Ok(temp_auth) = i64::from_str_radix(&temp_auth_hex_string, 16) {
            sid = format!("{}-{}", sid, temp_auth);
        } else {
            return None;
        }
    }
    Some(sid)
}

fn format_duration(days: f64) -> String {
    let whole_days = days.trunc() as u64;
    let hours = ((days - whole_days as f64) * 24.0).round();
    let whole_hours = hours.trunc() as u64;
    let minutes = ((hours - whole_hours as f64) * 60.0).round() as u64;

    let mut result: Vec<String> = Vec::new();

    if whole_days > 0 {
        result.push(format!("{} days", whole_days));
    }

    if whole_hours > 0 {
        result.push(format!("{} hours", whole_hours));
    }

    if minutes > 0 {
        result.push(format!("{} minutes", minutes));
    }

    result.join(", ")
}

impl SrumAnalyser {
    pub fn new(srum_path: PathBuf, software_hive_path: PathBuf) -> Self {
        Self {
            srum_path,
            software_hive_path,
        }
    }

    pub fn parse_srum_database(&self) -> Result<SrumDbInfo, Error> {
        // Load the SRUM ESE database
        let mut ese_db_parser = EsedbParser::load(&self.srum_path)
            .with_context(|| "unable to load the ESE database")?;

        let srum_data = ese_db_parser.parse();

        //Load the SOFTWARE hive
        let mut registry_parser = HveParser::load(&self.software_hive_path)
            .with_context(|| "unable to load the SOFTWARE hive")?;
        cs_eprintln!(
            "[+] SOFTWARE hive loaded from {:?}",
            fs::canonicalize(&self.software_hive_path).expect("could not get absolute path")
        );

        cs_eprintln!("[+] Parsing the SOFTWARE registry hive...");

        let mut srum_reg_info: SrumRegInfo = registry_parser
            .parse_srum_entries()
            .with_context(|| "unable to parse the SRUM regitry information")?;

        let srum_parameters_reg = srum_reg_info
            .global_parameters
            .as_object_mut()
            .with_context(|| "the SRUM parameters listed in the registry should be JSON objects")?;

        let srum_extensions_reg = srum_reg_info
            .extensions
            .as_object_mut()
            .with_context(|| "the SRUM extension listed in the registry should be JSON objects")?;

        let mut table_data_details = BTreeMap::new();

        // Global SRUM parameters
        for (table_guid, extension) in srum_extensions_reg.iter() {
            let table_name = extension["(default)"]
                .as_str()
                .with_context(|| "unable to get the data of the (default) registry value")?;
            let dll_name = extension["DllName"]
                .as_str()
                .with_context(|| "unable to get the data of the DllName registry value")?;

            // Check if the table has a long term capability
            if extension.get("LastLongTermUpdate").is_some() {
                // Calculate the long term retention period
                let mut t2_long_term_period = srum_parameters_reg["Tier2LongTermPeriod"]
                    .as_f64()
                    .with_context(|| {
                    "the default value for Tier2LongTermPeriod could not be retrieved"
                })?;

                if let Some(extension_t2_long_term_period) = extension.get("Tier2LongTermPeriod") {
                    t2_long_term_period =
                        extension_t2_long_term_period.as_f64().with_context(|| {
                            "the value for Tier2LongTermPeriod could not be retrieved"
                        })?;
                }

                let mut t2_long_term_max_entries = srum_parameters_reg["Tier2LongTermMaxEntries"]
                    .as_f64()
                    .with_context(|| {
                        "the default value for Tier2LongTermMaxEntries could not be retrieved"
                    })?;

                if let Some(extension_t2_long_term_max_entries) =
                    extension.get("Tier2LongTermMaxEntries")
                {
                    t2_long_term_max_entries = extension_t2_long_term_max_entries
                        .as_f64()
                        .with_context(|| {
                            "the value for Tier2LongTermMaxEntries could not be retrieved"
                        })?;
                }

                let long_term_retention_time =
                    t2_long_term_period * t2_long_term_max_entries / 3600.0 / 24.0;
                let table_guid_long_term = format!("{}LT", table_guid);
                let table_name_long_term = format!("{} (Long Term)", table_name);

                let td = TableDetails {
                    table_name: table_name_long_term,
                    dll_path: Some(dll_name.to_string()),
                    from: None,
                    to: None,
                    retention_time_days: Some(long_term_retention_time),
                };
                table_data_details.insert(table_guid_long_term, td);
            }

            // Calculate the retention time
            let mut t2_period = srum_parameters_reg["Tier2Period"]
                .as_f64()
                .with_context(|| "the default value for Tier2Period could not be retrieved")?;

            if let Some(extension_t2_period) = extension.get("Tier2Period") {
                t2_period = extension_t2_period
                    .as_f64()
                    .with_context(|| "the value for Tier2Period could not be retrieved")?;
            }

            let mut t2_max_entries = srum_parameters_reg["Tier2MaxEntries"]
                .as_f64()
                .with_context(|| "the default value for Tier2MaxEntries could not be retrieved")?;

            if let Some(extension_t2_max_entries) = extension.get("Tier2MaxEntries") {
                t2_max_entries = extension_t2_max_entries
                    .as_f64()
                    .with_context(|| "the value for Tier2MaxEntries could not be retrieved")?;
            }

            let retention_time = t2_period * t2_max_entries / 3600.0 / 24.0;

            let td = TableDetails {
                table_name: table_name.to_string(),
                dll_path: Some(dll_name.to_string()),
                from: None,
                to: None,
                retention_time_days: Some(retention_time),
            };
            table_data_details.insert(table_guid.clone(), td);
        }

        let sru_db_id_map_table_info = ese_db_parser
            .parse_sru_db_id_map_table()
            .with_context(|| "unable to parse the SruDbIdMapTable table")?;

        cs_eprintln!("[+] Analysing the SRUM database...");

        let mut result = Vec::new();

        for srum_value in srum_data {
            match srum_value {
                Ok(mut srum_entry) => {
                    if let Some(app_id_str) =
                        srum_entry.get("AppId").map(|app_id| app_id.to_string())
                    {
                        let app_name = sru_db_id_map_table_info
                            .get(&app_id_str)
                            .and_then(|app_map| app_map.id_blob_as_string.clone());

                        if let Some(app_name) = app_name {
                            srum_entry.insert("AppName".to_string(), json!(app_name));
                        } else {
                            srum_entry.insert("AppName".to_string(), Json::Null);
                        }
                    }
                    if let Some(user_id_str) =
                        srum_entry.get("UserId").map(|user_id| user_id.to_string())
                    {
                        let user_id_sid = sru_db_id_map_table_info
                            .get(&user_id_str)
                            .and_then(|user_map| user_map.id_blob.clone());

                        if let Some(user_id_sid) = user_id_sid {
                            if let Some(sid) = bytes_to_sid_string(&user_id_sid) {
                                srum_entry.insert("UserSID".to_string(), Json::String(sid.clone()));

                                let content_user = srum_reg_info.user_info[sid].clone();
                                let username = &content_user["Username"];

                                srum_entry.insert("UserName".to_string(), username.clone());
                            } else {
                                srum_entry.insert("UserName".to_string(), Json::Null);
                            }
                        } else {
                            srum_entry.insert("UserName".to_string(), Json::Null);
                        }
                    }
                    if let Some(table_name_str) =
                        srum_entry.get("Table").and_then(|table| table.as_str())
                    {
                        let table_name = table_name_str.to_string();
                        let mut table_name_mut = table_name_str.to_string();

                        if table_name_str.starts_with('{') {
                            if table_name_str.ends_with("LT") {
                                let table_name_description = &srum_extensions_reg
                                    [&table_name.replace("}LT", "}")]["(default)"]
                                    .as_str()
                                    .with_context(|| {
                                        "unable to get the table name from the SRUM database"
                                    })?;

                                table_name_mut = format!("{} (Long Term)", table_name_description);

                                srum_entry.insert(
                                    "TableName".to_string(),
                                    Json::String(table_name_mut.clone()),
                                );
                            } else {
                                let table_name_description =
                                    &srum_extensions_reg[&table_name]["(default)"];
                                srum_entry.insert(
                                    "TableName".to_string(),
                                    table_name_description.clone(),
                                );
                            }
                        } else {
                            srum_entry
                                .insert("TableName".to_string(), Json::String(table_name.clone()));
                        }

                        let dll_name =
                            if let Some(extension_entry) = srum_extensions_reg.get(&table_name) {
                                extension_entry
                                    .get("DllName")
                                    .map(|dll_path| dll_path.to_string())
                            } else {
                                None
                            };

                        // Get the timeframe of the data for each table
                        if let Some(timestamp_str) =
                            srum_entry.get("TimeStamp").and_then(|ts| ts.as_str())
                        {
                            let table_details = table_data_details
                                .entry(table_name)
                                .or_insert_with(|| TableDetails {
                                    table_name: table_name_mut.clone(),
                                    dll_path: dll_name,
                                    from: None,
                                    to: None,
                                    retention_time_days: None,
                                });

                            let mut min_ts_table = table_details.from;
                            let mut max_ts_table = table_details.to;

                            // Parse the timestamp string into a DateTime<Utc> object
                            if let Ok(timestamp) = DateTime::parse_from_rfc3339(timestamp_str) {
                                // Update min and max timestamps
                                let ts = DateTime::from(timestamp);

                                if let Some(min) = min_ts_table.as_ref() {
                                    if timestamp < *min {
                                        min_ts_table = Some(ts);
                                    }
                                } else {
                                    min_ts_table = Some(ts);
                                }

                                if let Some(max) = max_ts_table.as_ref() {
                                    if timestamp > *max {
                                        max_ts_table = Some(ts);
                                    }
                                } else {
                                    max_ts_table = Some(ts);
                                }
                            }

                            if let Some(min_ts_table) = min_ts_table {
                                table_details.from = Some(min_ts_table);
                            }

                            if let Some(max_ts_table) = max_ts_table {
                                table_details.to = Some(max_ts_table);
                            }
                        }
                    }

                    let win_ts_column_names = ["EndTime", "ConnectStartTime", "StartTime"];

                    for win_ts_column_name in win_ts_column_names {
                        if let Some(Json::Number(win_ts)) = srum_entry.get(win_ts_column_name) {
                            // Check if it's an integer
                            if let Some(integer) = win_ts.as_i64() {
                                let datetime = win32_ts_to_datetime(integer as u64).with_context(
                                    || "unable to convert Windows timestamp column value to DateTime",
                                )?;
                                let datetime_form =
                                    datetime.to_rfc3339_opts(SecondsFormat::Secs, true);

                                srum_entry.insert(
                                    win_ts_column_name.to_string(),
                                    Json::String(datetime_form),
                                );
                            }
                        }
                    }
                    result.push(srum_entry);
                }
                Err(e) => bail!(e),
            }
        }

        let mut std_table_details = Table::new();
        std_table_details.add_row(Row::new(vec![
            Cell::new("Table GUID"),
            Cell::new("Table Name"),
            Cell::new("DLL Path"),
            Cell::new("Timeframe of the data"),
            Cell::new("Expected Retention Time"),
        ]));

        for (table_guid, td) in table_data_details.iter() {
            let tf_str = if let (Some(from), Some(to)) = (td.from, td.to) {
                format!("{}\n{}", from, to)
            } else {
                "No records".to_string()
            };

            let formatted_duration = format_duration(td.retention_time_days.unwrap_or_default());

            std_table_details.add_row(Row::new(vec![
                Cell::new(table_guid),
                Cell::new(&td.table_name.to_string()),
                Cell::new(&td.dll_path.clone().unwrap_or_default()),
                Cell::new(&tf_str),
                Cell::new(formatted_duration.as_str()),
            ]));
        }

        Ok(SrumDbInfo {
            table_details: std_table_details,
            db_content: json!(result),
        })
    }
}
