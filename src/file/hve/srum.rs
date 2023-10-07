use anyhow::Context;
use notatin::cell_key_node::CellKeyNode;
use notatin::cell_value::CellValue;
use serde_json::json;
use serde_json::Value as Json;
use std::path::Path;

#[derive(Debug)]
pub struct SrumRegInfo {
    pub global_parameters: Json,
    pub extensions: Json,
    pub user_info: Json,
}

// A helper function for getting string values from registry keys
fn string_value_from_key(key: &CellKeyNode, value_name: &str) -> crate::Result<Option<String>> {
    // Check if the registry value name exists
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

impl super::Parser {
    pub fn parse_srum_entries(&mut self) -> crate::Result<SrumRegInfo> {
        // Get SRUM global parameters
        let key_srum_parameters = self
            .inner
            .get_key(
                r"Microsoft\Windows NT\CurrentVersion\SRUM\Parameters",
                false,
            )?
            .ok_or(anyhow!("Could not find the SRUM Parameters registry key!"))?;

        let reg_values_srum_parameters = key_srum_parameters.value_iter();

        // Default parameters
        let mut global_parameters = json!({
            "Tier1Period": 60,
            "Tier2Period": 3600,
            "Tier2MaxEntries": 1440,
            "Tier2LongTermPeriod": 604800,
            "Tier2LongTermMaxEntries": 260
        });

        for key_value in reg_values_srum_parameters {
            let key_value_content = key_value.get_content().0;

            match key_value_content {
                CellValue::Binary(reg_data) => {
                    global_parameters[key_value.get_pretty_name()] = serde_json::to_value(reg_data)
                        .with_context(|| "unable to convert a Binary entry from the SRUM registry values into a JSON object")?;
                }
                CellValue::U32(reg_data) => {
                    global_parameters[key_value.get_pretty_name()] = json!(reg_data);
                }
                CellValue::U64(reg_data) => {
                    global_parameters[key_value.get_pretty_name()] = json!(reg_data);
                }
                CellValue::I32(reg_data) => {
                    global_parameters[key_value.get_pretty_name()] = json!(reg_data);
                }
                CellValue::I64(reg_data) => {
                    global_parameters[key_value.get_pretty_name()] = json!(reg_data);
                }
                CellValue::String(reg_data) => {
                    global_parameters[key_value.get_pretty_name()] = json!(reg_data);
                }
                CellValue::MultiString(reg_data) => {
                    global_parameters[key_value.get_pretty_name()] = serde_json::to_value(reg_data)
                        .with_context(|| "unable to convert a MultiString entry from the SRUM registry values into a JSON object")?;
                }
                CellValue::None | CellValue::Error => {
                    global_parameters[key_value.get_pretty_name()] = Json::Null;
                }
            };
        }

        // Get and parse data related to the SRUM extensions
        let mut key_srum_extensions = self
            .inner
            .get_key(
                r"Microsoft\Windows NT\CurrentVersion\SRUM\Extensions",
                false,
            )?
            .ok_or(anyhow!("Could not find the SRUM Extensions registry key!"))?;

        let mut extensions = json!({});

        let subkeys = key_srum_extensions.read_sub_keys(&mut self.inner);

        for key in subkeys {
            let reg_value_uppercase = key.key_name.to_uppercase();
            extensions[key.key_name.to_uppercase()] = json!({});

            for key_value in key.value_iter() {
                let key_value_content = key_value.get_content().0;

                match key_value_content {
                    CellValue::Binary(reg_data) => {
                        extensions[&reg_value_uppercase][key_value.get_pretty_name()] =
                            serde_json::to_value(reg_data).with_context(|| {
                                "unable to store a binary entry from the SRUM registry values"
                            })?;
                    }
                    CellValue::U32(reg_data) => {
                        extensions[&reg_value_uppercase][key_value.get_pretty_name()] =
                            json!(reg_data);
                    }
                    CellValue::U64(reg_data) => {
                        extensions[&reg_value_uppercase][key_value.get_pretty_name()] =
                            json!(reg_data);
                    }
                    CellValue::I32(reg_data) => {
                        extensions[&reg_value_uppercase][key_value.get_pretty_name()] =
                            json!(reg_data);
                    }
                    CellValue::I64(reg_data) => {
                        extensions[&reg_value_uppercase][key_value.get_pretty_name()] =
                            json!(reg_data);
                    }
                    CellValue::String(reg_data) => {
                        extensions[&reg_value_uppercase][key_value.get_pretty_name()] =
                            Json::String(reg_data);
                    }
                    CellValue::MultiString(reg_data) => {
                        extensions[&reg_value_uppercase][key_value.get_pretty_name()] =
                            serde_json::to_value(reg_data).with_context(|| {
                                "unable to store a MultiString entry from the SRUM registry values"
                            })?;
                    }
                    CellValue::None | CellValue::Error => {
                        extensions[&reg_value_uppercase][key_value.get_pretty_name()] = Json::Null;
                    }
                };
            }
        }

        // Get Users GUID from the SOFTWARE Registry Hive
        let mut key_profile_list = self
            .inner
            .get_key(r"Microsoft\Windows NT\CurrentVersion\ProfileList", false)?
            .ok_or(anyhow!("Could not find the ProfileList key!"))?;

        let subkeys = key_profile_list.read_sub_keys(&mut self.inner);

        let mut user_info = json!({});

        for key in subkeys {
            // Check if the registry value name SID exists
            let sid = if let Some(key_value) = key.get_value("Sid") {
                match key_value.get_content().0 {
                    notatin::cell_value::CellValue::Binary(bytes) => {
                        bytes.iter().map(|byte| format!("{:02}", byte)).collect()
                    }
                    _ => Json::Null,
                }
            } else {
                Json::Null
            };

            let profile_image_path = string_value_from_key(&key, "ProfileImagePath")?
                .with_context(|| format!("Could not get ProfileImagePath for {}", key.key_name))?
                // to get the username afterwards using file_name()
                .replace('\\', "//");

            let username = if let Some(filename) = Path::new(&profile_image_path).file_name() {
                Json::String(filename.to_str().unwrap_or_default().to_string())
            } else {
                Json::Null
            };

            let guid_user = key.key_name;

            user_info[guid_user] = json!({
                "GUID": guid_user,
                "SID": sid,
                "Username": username,
            });
        }

        Ok(SrumRegInfo {
            global_parameters,
            extensions,
            user_info,
        })
    }
}
