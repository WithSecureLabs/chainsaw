use super::ChainsawRule;
use super::Detection;
use super::Events;
use super::HuntOpts;
use crate::util::RULE_PREFIX;
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;
use tau_engine::Value as Tau;
use tau_engine::{AsValue, Document};
extern crate ajson;

pub struct Wrapper<'a>(&'a serde_json::Value);
impl<'a> Document for Wrapper<'a> {
    fn find(&self, key: &str) -> Option<Tau<'_>> {
        self.0.get(key).map(|v| v.as_value())
    }
}

fn split_tag(tag_name: String, target: usize) -> String {
    let mut count = 0;
    let mut chars = Vec::with_capacity(tag_name.len());
    for char in tag_name.chars() {
        count += 1;
        if count > target && char.is_whitespace() {
            count = 0;
            chars.push('\n');
        } else {
            chars.push(char);
        }
    }
    chars.into_iter().collect()
}

fn get_tau_matches(
    mut data: serde_json::Value,
    chainsaw_rules: &[ChainsawRule],
) -> Option<(String, String)> {
    let mut matches = vec![];
    let mut authors = vec![];

    // TAU specific fix to make sure raw.ex.name is set to just the image name, not the full path
    if let Some(name) = data.get("raw.ex.name") {
        let re = Regex::new(r"([a-zA-Z0-9]+\.exe)").expect("Regex failed to build");
        if let Some(exe_name) = re.find(&name.to_string()) {
            data["raw.ex.name"] = json!(exe_name.as_str())
        }
    };
    // Check the doc for any tau rule matches
    for rule in chainsaw_rules {
        if rule.logic.matches(&Wrapper(&data)) {
            if rule.tag.len() > 20 {
                let title = split_tag(rule.tag.clone(), 20);
                matches.push(format!("{}{}", RULE_PREFIX, title));
            } else {
                matches.push(format!("{}{}", RULE_PREFIX, rule.tag.clone()));
            }
            // To comply to the sigma DRL we need to display rule author information
            if let Some(x) = &rule.authors {
                authors.push(format!("{}{}", RULE_PREFIX, x.join("\n")))
            } else {
                authors.push(format!("{}Unknown", RULE_PREFIX));
            }
        } else {
            continue;
        }
    }
    if matches.is_empty() {
        return None;
    }
    // Flatten vec here
    Some((matches.join("\n"), authors.join("\n")))
}

fn format_time(event_time: String) -> String {
    let chunks = event_time.rsplit('.').last();
    match chunks {
        Some(e) => e.replace("T", " ").replace('"', ""),
        None => event_time,
    }
}

pub fn extract_logon_fields(event: &serde_json::value::Value) -> Option<HashMap<String, String>> {
    // Extract the key fields from login events and load them into a struct and return
    // We don't need to return column headers as they can be derived from the struct fields later

    let mut values = HashMap::new();
    values.insert(
        "logon_type".to_string(),
        event["Event"]["EventData"]["LogonType"].to_string(),
    );
    values.insert(
        "target_username".to_string(),
        event["Event"]["EventData"]["TargetUserName"].to_string(),
    );
    values.insert(
        "workstation_name".to_string(),
        event["Event"]["EventData"]["WorkstationName"].to_string(),
    );
    values.insert(
        "ip_address".to_string(),
        event["Event"]["EventData"]["IpAddress"].to_string(),
    );
    values.insert(
        "computer".to_string(),
        event["Event"]["System"]["Computer"].to_string(),
    );
    values.insert(
        "system_time".to_string(),
        format_time(
            event["Event"]["System"]["TimeCreated"]["#attributes"]["SystemTime"].to_string(),
        ),
    );
    values.insert(
        "process_name".to_string(),
        event["Event"]["EventData"]["ProcessName"].to_string(),
    );
    Some(values)
}

pub fn detect_created_users(event: &serde_json::value::Value, event_id: &u64) -> Option<Detection> {
    let title = String::from("(Built-in Logic) - New User Created");
    let headers = vec![
        "system_time".to_string(),
        "id".to_string(),
        "computer".to_string(),
        "target_username".to_string(),
        "user_sid".to_string(),
    ];
    let values = vec![
        format_time(
            event["Event"]["System"]["TimeCreated"]["#attributes"]["SystemTime"].to_string(),
        ),
        event_id.to_string(),
        event["Event"]["System"]["Computer"].to_string(),
        event["Event"]["EventData"]["TargetUserName"].to_string(),
        event["Event"]["EventData"]["TargetSid"].to_string(),
    ];
    let ret = Detection {
        headers,
        title,
        values,
    };

    Some(ret)
}

fn format_field_length(mut data: String, full_output: &bool, length: usize) -> String {
    // Take the context_field and format it for printing. Remove newlines, break into even chunks etc.
    // If this is a scheduled task we need to parse the XML to make it more readable

    data = data
        .replace("\n", "")
        .replace("\r", "")
        .replace("\t", "")
        .replace("  ", " ")
        .chars()
        .collect::<Vec<char>>()
        .chunks(length)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<String>>()
        .join("\n");

    let truncate_len = 1000;

    if !*full_output && data.len() > truncate_len {
        data.truncate(truncate_len);
        data.push_str("...\n\n(use --full to show all content)");
    }
    data
}

pub fn detect_tau_matches(
    event: &serde_json::value::Value,
    event_id: u64,
    chainsaw_rules: &[ChainsawRule],
    id_mappings: &HashMap<u64, Events>,
    full_output: &bool,
    col_width: i32,
    show_authors: &bool,
) -> Option<Detection> {
    let command_line;
    let mut headers = vec![];
    let title;

    // Build JSON doc dynamically from the fields provided in the mapping file
    let mut doc = json!({});
    match id_mappings.get(&event_id) {
        Some(fields) => {
            // Get the provider and make sure it matches the mapping file this EventID
            // This allows us to make sure that we don't process EventIDs from other providers
            if let Some(provider) =
                ajson::get(&event.to_string(), "Event.System.Provider.#attributes.Name")
            {
                if provider.to_string() != fields.provider {
                    return None;
                }
            } else {
                //cs_println!("ERROR Could not find provider")
                return None;
            }

            // Loop through every specified field and attempt to match to the current event doc
            for (k, v) in &fields.search_fields {
                let h = match ajson::get(&event.to_string(), v) {
                    Some(h) => h.to_string(),
                    None => {
                        // cs_println!("{} - could not match: {}", event_id, v);
                        // cs_println!("{:?}", event);
                        continue;
                    }
                };
                doc[k] = json!(h);
            }
            doc["EventID"] = json!(event_id);

            // Find the context_field and extract it's value from the event
            command_line = match fields.table_headers.get("context_field") {
                Some(a) => match ajson::get(&event.to_string(), a) {
                    Some(v) => {
                        if v.to_string().is_empty() {
                            "<empty>".to_string()
                        } else {
                            format_field_length(v.to_string(), full_output, col_width as usize)
                        }
                    }
                    None => "context_field not found!".to_string(),
                },
                None => "context_field not set".to_string(),
            };
        }
        None => return None,
    };

    let (hits, authors) = match get_tau_matches(doc, chainsaw_rules) {
        Some(ret) => ret,
        None => return None,
    };

    let mut values = vec![];
    match id_mappings.get(&event_id) {
        Some(fields) => {
            // Set table title
            title = format!("(External Rule) - {}", fields.title.clone());

            // The first column should always be the system time
            headers.push("system_time".to_string());
            match ajson::get(
                &event.to_string(),
                "Event.System.TimeCreated.#attributes.SystemTime",
            ) {
                // The normal event time includes milliseconds which is un-necessary
                Some(time) => {
                    values.push(format_time(time.to_string()));
                }
                None => values.push("<system time not found>".to_string()),
            }
            // Set hardcoded table headers and values
            headers.push("id".to_string());
            headers.push("detection_rules".to_string());
            if *show_authors {
                headers.push("rule_authors".to_string());
            }
            headers.push("computer_name".to_string());
            match fields.table_headers.get("context_field") {
                Some(v) => headers.push(v.to_string()),
                None => headers.push("context_field".to_string()),
            };

            values.push(event_id.to_string());
            values.push(hits);
            if *show_authors {
                values.push(authors);
            }
            values.push(event["Event"]["System"]["Computer"].to_string());
            values.push(command_line);
            for (k, v) in &fields.table_headers {
                if k == "context_field" {
                    continue;
                }
                // Insert the table headers
                headers.push(k.to_string());
                // Insert the table values
                match ajson::get(&event.to_string(), v) {
                    Some(b) => {
                        let b = b.to_string();
                        if b.is_empty() {
                            values.push("<empty>".to_string())
                        } else {
                            values.push(format_field_length(b, full_output, col_width as usize))
                        }
                    }
                    None => values.push("Invalid Mapping".to_string()),
                };
            }
        }
        None => return None,
    }
    let ret = Detection {
        headers,
        title,
        values,
    };

    Some(ret)
}

pub fn detect_group_changes(event: &serde_json::value::Value, e_id: &u64) -> Option<Detection> {
    let group = event["Event"]["EventData"]["TargetUserName"].to_string();

    // Filter for Admin groups and RDP groups
    if !group.contains("Admin") && !group.contains("Remote Desktop") {
        return None;
    }
    let headers = vec![
        "system_time".to_string(),
        "id".to_string(),
        "computer".to_string(),
        "change_type".to_string(),
        "user_sid".to_string(),
        "target_group".to_string(),
    ];
    let title = String::from("(Built-in Logic) - User added to interesting group");

    let change_type;
    match e_id {
        4728 => change_type = "User added to global group".to_string(),
        4732 => change_type = "User added to local group".to_string(),
        4756 => change_type = "User added to universal group".to_string(),
        _ => return None,
    }

    let values = vec![
        format_time(
            event["Event"]["System"]["TimeCreated"]["#attributes"]["SystemTime"].to_string(),
        ),
        e_id.to_string(),
        event["Event"]["System"]["Computer"].to_string(),
        change_type,
        event["Event"]["EventData"]["MemberSid"].to_string(),
        event["Event"]["EventData"]["TargetUserName"].to_string(),
    ];

    // Build detection to return
    let ret = Detection {
        headers,
        title,
        values,
    };

    Some(ret)
}

pub fn detect_cleared_logs(event: &serde_json::value::Value, e_id: &u64) -> Option<Detection> {
    if event["Event"]["UserData"]["LogFileCleared"]["SubjectUserName"].is_null() {
        return None;
    }

    let headers = vec![
        "system_time".to_string(),
        "id".to_string(),
        "computer".to_string(),
        "subject_user".to_string(),
    ];

    let title = match e_id {
        1102 => "(Built-in Logic) - Security audit log was cleared".to_string(),
        104 => "(Built-in Logic) - System log was cleared".to_string(),
        _ => return None,
    };

    let values = vec![
        format_time(
            event["Event"]["System"]["TimeCreated"]["#attributes"]["SystemTime"].to_string(),
        ),
        e_id.to_string(),
        event["Event"]["System"]["Computer"].to_string(),
        event["Event"]["UserData"]["LogFileCleared"]["SubjectUserName"].to_string(),
    ];

    let ret = Detection {
        headers,
        title,
        values,
    };

    Some(ret)
}

pub fn detect_stopped_service(
    event: &serde_json::value::Value,
    event_id: &u64,
) -> Option<Detection> {
    let action = event["Event"]["EventData"]["param2"].to_string();
    let service_name = event["Event"]["EventData"]["param1"].to_string();
    let title = String::from("(Built-in Logic) - Event Log Service Stopped");

    // Only check for the windows event logs service being stopped
    // We can add more services here as needed
    if !service_name.contains("Windows Event Log") || !action.contains("disabled") {
        return None;
    }

    let headers = vec![
        "system_time".to_string(),
        "id".to_string(),
        "computer".to_string(),
        "service_name".to_string(),
        "status".to_string(),
    ];

    let values = vec![
        format_time(
            event["Event"]["System"]["TimeCreated"]["#attributes"]["SystemTime"].to_string(),
        ),
        event_id.to_string(),
        event["Event"]["System"]["Computer"].to_string(),
        service_name,
        action,
    ];

    let ret = Detection {
        headers,
        title,
        values,
    };

    Some(ret)
}

pub fn detect_defender_detections(
    event: &serde_json::value::Value,
    e_id: &u64,
    full_output: bool,
    col_width: i32,
) -> Option<Detection> {
    let headers = vec![
        "system_time".to_string(),
        "id".to_string(),
        "computer".to_string(),
        "threat_name".to_string(),
        "threat_file".to_string(),
        "user".to_string(),
    ];
    let title = String::from("(Built-in Logic) - Windows Defender Detections");

    let mut threat_path = event["Event"]["EventData"]["Path"].to_string();

    threat_path = format_field_length(threat_path, &full_output, col_width as usize);

    let values = vec![
        format_time(
            event["Event"]["System"]["TimeCreated"]["#attributes"]["SystemTime"].to_string(),
        ),
        e_id.to_string(),
        event["Event"]["System"]["Computer"].to_string(),
        event["Event"]["EventData"]["Threat Name"].to_string(),
        threat_path,
        event["Event"]["EventData"]["Detection User"].to_string(),
    ];

    let ret = Detection {
        headers,
        title,
        values,
    };

    Some(ret)
}

pub fn detect_ultralight_detections(
    event: &serde_json::value::Value,
    e_id: &u64,
    full_output: bool,
    col_width: i32,
) -> Option<Detection> {
    let headers = vec![
        "system_time".to_string(),
        "id".to_string(),
        "computer".to_string(),
        "threat_name".to_string(),
        "threat_file".to_string(),
        "sha1".to_string(),
    ];
    let title = String::from("(Built-in Logic)) - F-Secure AV Detections");

    // Access F-Secure detection data which is in a nested json string
    let detection_data = match event["Event"]["EventData"]["rv"].as_str() {
        Some(x) => match serde_json::from_str::<Value>(x) {
            Ok(y) => y,
            Err(_) => return None,
        },
        None => return None,
    };

    let threat_path = format_field_length(
        detection_data["obj"]["ref"].to_string(),
        &full_output,
        col_width as usize,
    );

    let values = vec![
        format_time(
            event["Event"]["System"]["TimeCreated"]["#attributes"]["SystemTime"].to_string(),
        ),
        e_id.to_string(),
        event["Event"]["System"]["Computer"].to_string(),
        detection_data["iname"].to_string(),
        threat_path,
        detection_data["obj"]["sha1"].to_string(),
    ];

    let ret = Detection {
        headers,
        title,
        values,
    };

    Some(ret)
}

pub fn detect_kaspersky_detections(
    event: &serde_json::value::Value,
    e_id: &u64,
    full_output: bool,
    col_width: i32,
) -> Option<Detection> {
    let headers = vec![
        "system_time".to_string(),
        "id".to_string(),
        "computer".to_string(),
        "threat_file".to_string(),
        "threat_name".to_string(),
    ];
    let title = String::from("(Built-in Logic) - Kaspersky AV Detections");

    let threat_path;
    let threat_name;

    // Kaspersky puts the relevant data in a Vec. Here we locate it and extract the key fields
    if let Some(threat_data) = ajson::get(&event.to_string(), "Event.EventData.Data.#text") {
        threat_path = match threat_data.to_vec().get(0) {
            Some(a) => a.clone(),
            None => return None,
        };
        threat_name = match threat_data.to_vec().get(1) {
            Some(a) => a.clone(),
            None => return None,
        }
    } else {
        return None;
    }

    let threat_path =
        format_field_length(threat_path.to_string(), &full_output, col_width as usize);

    let values = vec![
        format_time(
            event["Event"]["System"]["TimeCreated"]["#attributes"]["SystemTime"].to_string(),
        ),
        e_id.to_string(),
        event["Event"]["System"]["Computer"].to_string(),
        threat_path,
        threat_name.to_string(),
    ];

    let ret = Detection {
        headers,
        title,
        values,
    };

    Some(ret)
}

pub fn detect_sophos_detections(
    event: &serde_json::value::Value,
    e_id: &u64,
    full_output: bool,
    col_width: i32,
) -> Option<Detection> {
    let headers = vec![
        "system_time".to_string(),
        "id".to_string(),
        "computer".to_string(),
        "threat_type".to_string(),
        "threat_file".to_string(),
        "threat_name".to_string(),
    ];
    let title = String::from("(Built-in Logic) - Sophos AV Detections");

    let threat_path;
    let threat_name;
    let threat_type;

    // Sophos puts the relevant data in a Vec. Here we locate it and extract the key fields
    if let Some(threat_data) = ajson::get(&event.to_string(), "Event.EventData.Data.#text") {
        threat_type = match threat_data.to_vec().get(0) {
            Some(a) => a.clone(),
            None => return None,
        };
        threat_path = match threat_data.to_vec().get(1) {
            Some(a) => a.clone(),
            None => return None,
        };
        threat_name = match threat_data.to_vec().get(2) {
            Some(a) => a.clone(),
            None => return None,
        }
    } else {
        return None;
    }

    let threat_path =
        format_field_length(threat_path.to_string(), &full_output, col_width as usize);

    let values = vec![
        format_time(
            event["Event"]["System"]["TimeCreated"]["#attributes"]["SystemTime"].to_string(),
        ),
        e_id.to_string(),
        event["Event"]["System"]["Computer"].to_string(),
        threat_type.to_string(),
        threat_path,
        threat_name.to_string(),
    ];

    let ret = Detection {
        headers,
        title,
        values,
    };

    Some(ret)
}

pub fn detect_login_attacks(events: &[HashMap<String, String>]) -> Option<Vec<Detection>> {
    let mut logon_tracker = HashMap::new();
    let failed_limit = 5;

    // Add up number of failed logins for each user
    for event in events {
        let username = event["target_username"].clone();
        if username == "null" {
            continue;
        }
        *logon_tracker.entry(username).or_insert(0) += 1;
    }

    // Filter out accounts below failed limit
    logon_tracker.retain(|_, v| *v > failed_limit);

    if logon_tracker.keys().len() == 0 {
        return None;
    }

    let mut results = vec![];

    //Account Brute Forcing
    for (username, count) in &logon_tracker {
        let title = String::from("(Built-in Logic) - Account Brute Forcing");

        let headers = vec![
            "id".to_string(),
            "username".to_string(),
            "failed_login_count".to_string(),
        ];

        let values = vec!["4625".to_string(), username.clone(), count.to_string()];
        let ret = Detection {
            headers,
            title,
            values,
        };
        results.push(ret);
    }
    Some(results)
}

pub fn filter_lateral_movement(
    events: &[HashMap<String, String>],
    hunts: &HuntOpts,
) -> Option<Vec<Detection>> {
    let mut results = vec![];

    // Create a hashmap of logon types we will include
    let mut logon_types = HashMap::new();
    let mut title = String::from("(Built-in Logic) - RDP Logins");

    logon_types.insert("10".to_string(), "rdp (type 10)");

    if hunts.lateral_all {
        logon_types.insert("2".to_string(), "interactive (type 2)");
        logon_types.insert("3".to_string(), "network (type 3)");
        logon_types.insert("4".to_string(), "batch (type 4)");
        logon_types.insert("5".to_string(), "service (type 5)");
        logon_types.insert("7".to_string(), "unlock (type 7)");
        title = String::from("4624 Logins");
    }

    for event in events {
        if !logon_types.contains_key(&event["logon_type"]) {
            continue;
        }

        // Only show results where there's a source IP, this removes local events that cause noise
        if event["ip_address"] == "\"-\""
            || event["ip_address"] == "\"127.0.0.1\""
            || event["ip_address"] == "\"::1\""
        {
            continue;
        }

        // Filter out machine accounts to reduce noise
        if event["target_username"].to_string().ends_with("$\"") {
            continue;
        }

        let headers = vec![
            "system_time".to_string(),
            "id".to_string(),
            "workstation_name".to_string(),
            "target_username".to_string(),
            "source_ip".to_string(),
            "logon_type".to_string(),
        ];
        let values = vec![
            event["system_time"].to_string(),
            "4624".to_string(),
            event["workstation_name"].to_string(),
            event["target_username"].to_string(),
            event["ip_address"].to_string(),
            logon_types.get(&event["logon_type"])?.to_string(),
        ];
        let ret = Detection {
            headers,
            title: title.clone(),
            values,
        };
        results.push(ret);
    }

    Some(results)
}
