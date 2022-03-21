use std::collections::HashMap;
use std::fs::{create_dir_all, metadata, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::Result;
use chrono::NaiveDateTime;
use itertools::Itertools;
use prettytable::format;
use prettytable::row::Row;
use prettytable::Table;
use structopt::StructOpt;
use walkdir::WalkDir;

use crate::convert::{sigma, stalker};
use crate::util::RULE_PREFIX;
use crate::util::{get_evtx_files, get_progress_bar, large_event_logs, parse_evtx_file};

pub(crate) mod modules;

#[derive(StructOpt)]
pub struct HuntOpts {
    /// Specify an EVTX file, or a directory containing the EVTX files to search.
    /// If you specify a directory, all files matching *.evtx will be used.
    ///
    /// Specifying "win_default" will use "C:\Windows\System32\winevt\Logs\"
    pub evtx_path: PathBuf,

    /// Suppress all unnecessary output
    #[structopt(short = "q", long = "quiet")]
    pub quiet: bool,

    /// Skip EVTX file if chainsaw is unable to parse the records
    #[structopt(long = "ignore-errors")]
    pub ignore: bool,

    // Specify the detection rule directory to use
    //
    /// Specify a directory containing detection rules to use. All files matching *.yml will be used.
    #[structopt(short = "r", long = "rules")]
    pub rules_path: Option<PathBuf>,

    // Specify a mapping file
    //
    /// Specify the mapping file to use to with the specified detection rules.
    /// Required when using the --rule/-r flag
    #[structopt(short = "m", long = "mapping")]
    pub mapping_path: Option<PathBuf>,

    /// List additional 4624 events potentially relating to lateral movement
    #[structopt(long = "lateral-all")]
    pub lateral_all: bool,

    /// Save hunt output to individual CSV files in the specified directory
    #[structopt(long = "csv", group = "format")]
    pub csv: Option<PathBuf>,

    /// Show rule author information in table output
    #[structopt(long = "authors")]
    pub show_authors: bool,

    /// Show full event output, otherwise output is trunctated to improve readability
    #[structopt(long = "full")]
    pub full_output: bool,

    /// For each detection, output the associated event log entry and detection information in a JSON format
    #[structopt(short, long = "json", group = "format")]
    pub json: bool,

    /// Do not use inbuilt detection logic, only use the specified rules for detection
    #[structopt(long = "no-builtin")]
    pub disable_inbuilt_logic: bool,

    /// Change the maximum column width (default 40). Use this option if the table output is un-readable
    #[structopt(long = "col-width", default_value = "40")]
    pub col_width: i32,

    /// Start date for including events (UTC). Anything older than this is dropped. Format: YYYY-MM-DDTHH:MM:SS. Example: 2019-11-17T17:55:11
    #[structopt(long = "start-date")]
    pub start_date: Option<String>,

    /// End date for including events (UTC). Anything newer than this is dropped. Format: YYYY-MM-DDTHH:MM:SS. Example: 2019-11-17T17:55:11
    #[structopt(long = "end-date")]
    pub end_date: Option<String>,

    /// File to write output to, this is ignored by --csv
    #[structopt(long = "output")]
    pub output: Option<PathBuf>,
}

#[derive(Serialize)]
pub struct JsonDetection {
    detection: Vec<String>,
    event: serde_json::Value,
}

#[derive(Clone)]
pub struct Detection {
    headers: Vec<String>,
    title: String,
    values: Vec<String>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub struct ChainsawRule {
    pub level: Option<String>,
    #[serde(flatten)]
    pub logic: tau_engine::Rule,
    #[serde(alias = "title")]
    pub tag: String,
    pub status: Option<String>,
    pub authors: Option<Vec<String>>,
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct Events {
    provider: String,
    search_fields: HashMap<String, String>,
    table_headers: HashMap<String, String>,
    title: String,
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct Mapping {
    pub exclusions: Option<Vec<String>>,
    pub kind: String,
    pub mappings: HashMap<u64, Events>,
}

enum Provider {
    Defender,
    EventLogAction,
    FSecure,
    Kaspersky,
    SecurityAuditing,
    ServiceControl,
    Sophos,
}

pub enum RuleType {
    Stalker,
    Sigma,
}

impl RuleType {
    pub fn from(kind: &str) -> Option<RuleType> {
        match kind.to_lowercase().as_str() {
            "sigma" => Some(RuleType::Sigma),
            "stalker" => Some(RuleType::Stalker),
            &_ => None,
        }
    }
}

impl Provider {
    fn resolve(provider: Option<ajson::Value>) -> Option<Provider> {
        if let Some(p) = provider {
            match p.as_str() {
                "F-Secure Ultralight SDK" => return Some(Provider::FSecure),
                "Microsoft-Windows-Eventlog" => return Some(Provider::EventLogAction),
                "Microsoft-Windows-Security-Auditing" => return Some(Provider::SecurityAuditing),
                "Microsoft-Windows-Windows Defender" => return Some(Provider::Defender),
                "OnDemandScan" => return Some(Provider::Kaspersky),
                "Real-time file protection" => return Some(Provider::Kaspersky),
                "Service Control Manager" => return Some(Provider::ServiceControl),
                "Sophos Anti-Virus" => return Some(Provider::Sophos),
                &_ => return None,
            }
        }
        None
    }
}

pub fn det_to_json(
    det: Detection,
    event: serde_json::Value,
    target: &str,
) -> Result<JsonDetection> {
    let detection;
    match target {
        "rules" => {
            // Get field containing names of detection rules that fired
            let rules = match det.values.get(2) {
                Some(r) => r,
                None => return Err(anyhow!("Failed to get rules from detection!")),
            };
            detection = rules
                .replace("\n", " ")
                .split(RULE_PREFIX)
                .map(|s| s.trim_end())
                .map(|s| s.to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        "title" => {
            detection = vec![det.title];
        }
        _ => return Err(anyhow!("Unsupported target for det_to_json!")),
    }
    Ok(JsonDetection { detection, event })
}

pub fn run_hunt(opt: HuntOpts) -> Result<String> {
    // Main function for parsing and hunting through event logs
    let evtx_files = get_evtx_files(&opt.evtx_path)?;
    let mut det = None;
    let mut grouped_events = HashMap::new();
    let mut hunt_detections = Vec::new();
    let mut json_detections = Vec::new();
    let mut mapping_file = None;
    let mut sd_marker = None;
    let mut ed_marker = None;

    let time_format = "%Y-%m-%dT%H:%M:%S";

    // if start date filter is provided, validate that the provided string is a valid timestamp
    if let Some(x) = &opt.start_date {
        sd_marker = match NaiveDateTime::parse_from_str(x.as_str(), time_format) {
            Ok(a) => {
                cs_eprintln!("[+] Filtering out events before: {}", a);
                Some(a)
            }
            Err(e) => return Err(anyhow!("Error parsing provided start-date filter: {}", e)),
        }
    }

    // if end date filter is provided, validate that the provided string is a valid timestamp
    if let Some(x) = &opt.end_date {
        ed_marker = match NaiveDateTime::parse_from_str(x.as_str(), time_format) {
            Ok(a) => {
                cs_eprintln!("[+] Filtering out events after:  {}", a);
                Some(a)
            }
            Err(e) => return Err(anyhow!("Error parsing provided end-date filter: {}", e)),
        }
    }

    // If detection rules are provided we need to load, convert and apply mapping file
    let detection_rules = match &opt.rules_path {
        Some(rules) => {
            match opt.mapping_path.clone() {
                Some(file) => {
                    // Load and check mapping file
                    mapping_file = Some(get_mapping_file(&file)?);
                }
                None => {
                    return Err(anyhow!(
          "A mapping file must be specified when using detection rules, use --mapping to specify one"
      ));
                }
            };
            cs_eprintln!("[+] Converting detection rules...");
            // Load detection rules
            Some(load_detection_rules(
                rules,
                false,
                mapping_file.as_ref().expect("No mapping file"),
                false,
            )?)
        }
        None => {
            if opt.disable_inbuilt_logic {
                return Err(
          anyhow!(
          "In-built detection logic disabled (--no-builtin) but no detection rules provided! Use --rules to specify rules"),
        );
            }
            cs_eyellowln!("[!] Continuing without detection rules, no path provided");
            None
        }
    };
    if opt.disable_inbuilt_logic {
        cs_eyellowln!(
            "[!] Inbuilt detection logic disabled (--no-builtin). Only using specified rule files"
        );
    }

    if large_event_logs(&evtx_files) {
        cs_eyellowln!(
            "[!] Provided event logs are over 500MB in size. This will take a while to parse...",
        );
    }
    // Set up progress bar
    let pb = get_progress_bar(evtx_files.len() as u64, "Hunting".to_string());
    // Loop through EVTX files and perform actions
    for evtx in &evtx_files {
        pb.tick();
        // Parse EVTX files
        let mut parser = match parse_evtx_file(evtx) {
            Ok(a) => a,
            Err(e) => {
                if opt.ignore {
                    continue;
                }
                return Err(anyhow!("{:?} - {}", evtx, e));
            }
        };
        // Loop through records and hunt for suspicious indicators
        for record in parser.records_json_value() {
            let r = match record {
                Ok(record) => record,
                Err(_) => {
                    continue;
                }
            };
            // Perform start/end datetime filtering
            if sd_marker.is_some() || ed_marker.is_some() {
                let event_time = match NaiveDateTime::parse_from_str(
                    r.data["Event"]["System"]["TimeCreated_attributes"]["SystemTime"]
                        .as_str()
                        .unwrap(),
                    "%Y-%m-%dT%H:%M:%S%.6fZ",
                ) {
                    Ok(t) => t,
                    Err(_) => {
                        return Err(anyhow!(
          "Failed to parse datetime from supplied events. This shouldn't happen..."));
                    }
                };

                // Check if event is older than start date marker
                if let Some(sd) = sd_marker {
                    if event_time <= sd {
                        continue;
                    }
                }
                // Check if event is newer than end date marker
                if let Some(ed) = ed_marker {
                    if event_time >= ed {
                        continue;
                    }
                }
            }

            let e_id;

            // Event ID can be stored in two different locations
            if r.data["Event"]["System"]["EventID"]["#text"].is_null() {
                e_id = &r.data["Event"]["System"]["EventID"];
            } else {
                e_id = &r.data["Event"]["System"]["EventID"]["#text"];
            }

            // Convert event_id to u64 value
            let e_id = match e_id.as_u64() {
                Some(e) => e,
                None => continue,
            };
            if let Some(mapping) = &mapping_file {
                if mapping.mappings.contains_key(&e_id) {
                    if let Some(rules) = &detection_rules {
                        // Pass event doc and Detection rules to processor for rule detection
                        if let Some(det) = modules::detect_tau_matches(
                            &r.data,
                            e_id,
                            rules,
                            &mapping.mappings,
                            &opt.full_output,
                            opt.col_width,
                            &opt.show_authors,
                        ) {
                            if opt.json {
                                json_detections.push(det_to_json(
                                    det.clone(),
                                    r.data.clone(),
                                    "rules",
                                )?);
                            }
                            hunt_detections.push(det);
                        }
                    }
                }
            }
            if !opt.disable_inbuilt_logic {
                //
                // This is where we run hunt modules on evtx records
                // We either continue detect events and push them into Detection structs
                // or collect events for analysis across multiple evtx files
                // e.g. password-spraying
                //
                let raw_provider =
                    ajson::get(&r.data.to_string(), "Event.System.Provider_attributes.Name");
                if let Some(provider) = Provider::resolve(raw_provider) {
                    match provider {
                        // Get Defender AV Events
                        Provider::Defender => {
                            if e_id == 1116 {
                                det = modules::detect_defender_detections(
                                    &r.data,
                                    &e_id,
                                    opt.full_output,
                                    opt.col_width,
                                )
                            }
                        }
                        // Detect event logs being cleared
                        Provider::EventLogAction => {
                            if e_id == 1102 || e_id == 104 {
                                det = modules::detect_cleared_logs(&r.data, &e_id)
                            }
                        }
                        // Get F-Secure AV events
                        Provider::FSecure => {
                            if e_id == 2 {
                                det = modules::detect_ultralight_detections(
                                    &r.data,
                                    &e_id,
                                    opt.full_output,
                                    opt.col_width,
                                )
                            }
                        }
                        // Get Kaspersky AV Events
                        Provider::Kaspersky => {
                            if e_id == 3203 || e_id == 5203 {
                                det = modules::detect_kaspersky_detections(
                                    &r.data,
                                    &e_id,
                                    opt.full_output,
                                    opt.col_width,
                                )
                            }
                        }
                        Provider::SecurityAuditing => {
                            if e_id == 4728 || e_id == 4732 || e_id == 4756 {
                                det = modules::detect_group_changes(&r.data, &e_id)
                            } else if e_id == 4720 {
                                det = modules::detect_created_users(&r.data, &e_id)
                            } else if e_id == 4625 || e_id == 4624 {
                                if let Some(fields) = modules::extract_logon_fields(&r.data) {
                                    grouped_events
                                        .entry(e_id)
                                        .or_insert_with(Vec::new)
                                        .push(fields);
                                }
                            }
                        }
                        Provider::ServiceControl => {
                            if e_id == 7040 {
                                det = modules::detect_stopped_service(&r.data, &e_id)
                            }
                        }
                        // Get Sophos AV Events
                        Provider::Sophos => {
                            if e_id == 32 || e_id == 16 {
                                det = modules::detect_sophos_detections(
                                    &r.data,
                                    &e_id,
                                    opt.full_output,
                                    opt.col_width,
                                )
                            }
                        }
                    };
                    if let Some(d) = det {
                        if opt.json {
                            json_detections.push(det_to_json(d.clone(), r.data, "title")?);
                        }
                        hunt_detections.push(d);
                        det = None;
                    }
                }
            }
        }
        pb.inc(1);
    }
    // Finish the progress bar
    pb.finish();
    // Print or Write results
    if let Some(res) = post_process_hunt(grouped_events, &opt) {
        for r in res {
            hunt_detections.push(r);
        }
    };

    if let Some(dir) = opt.csv {
        save_hunt_results(dir, &hunt_detections)?;
    } else if opt.json {
        cs_print_json!(&json_detections)?;
    } else {
        print_hunt_results(&hunt_detections);
    }

    Ok(format!("\n[+] {} Detections found", hunt_detections.len()))
}

fn post_process_hunt(
    grouped_events: HashMap<u64, Vec<HashMap<String, String>>>,
    hunts: &HuntOpts,
) -> Option<Vec<Detection>> {
    // This is where we run detection hunts which span across multiple event records
    // e.g. detecting password spraying (multiple 4624 records)
    //
    // grouped_events format: HashMap<event_id, Vec<HashMap<field_name,value>>>
    //
    // Process 4625 Events
    let mut results = Vec::new();
    if !hunts.disable_inbuilt_logic {
        if let Some(a) = grouped_events.get(&4625) {
            let detections = match modules::detect_login_attacks(a) {
                Some(b) => b,
                None => vec![],
            };
            results.push(detections);
        }
        // Process 4624 Events
        if let Some(a) = grouped_events.get(&4624) {
            let detections = match modules::filter_lateral_movement(a, hunts) {
                Some(b) => b,
                None => vec![],
            };
            results.push(detections);
        }
    }
    if results.is_empty() {
        return None;
    }
    Some(results.into_iter().flatten().collect())
}

fn print_hunt_results(detections: &[Detection]) {
    // Create a uniq list of all hunt result titles so that we can aggregate
    let detection_titles: &Vec<String> = &detections
        .iter()
        .map(|x| x.title.clone())
        .unique()
        .collect();
    let format = format::FormatBuilder::new()
        .column_separator('│')
        .borders('│')
        .separators(
            &[format::LinePosition::Top],
            format::LineSeparator::new('─', '┬', '┌', '┐'),
        )
        .separators(
            &[format::LinePosition::Intern],
            format::LineSeparator::new('─', '┼', '├', '┤'),
        )
        .separators(
            &[format::LinePosition::Bottom],
            format::LineSeparator::new('─', '┴', '└', '┘'),
        )
        .padding(1, 1)
        .build();
    // Loop through uniq list of hunt results
    for title in detection_titles {
        let mut table = Table::new();
        table.set_format(format);
        let mut header = false;
        cs_greenln!("\n[+] Detection: {}", title);

        let mut unsorted_rows = vec![];
        // Loop through detection values and print in a table view
        for detection in detections {
            // Only group together results of the same hunt
            if detection.title != *title {
                continue;
            }
            if !header {
                // Header builder
                let mut headers = vec![];
                for c in &detection.headers {
                    let cell = cell!(c).style_spec("c");
                    headers.push(cell);
                }
                table.add_row(Row::new(headers));
                header = true;
            }
            // Values builder
            let mut values = vec![];
            for c in &detection.values {
                values.push(c);
            }
            unsorted_rows.push(values);
        }

        // Sort by timestamp to get into acending order
        unsorted_rows.sort_by(|a, b| a.first().cmp(&b.first()));

        // This code block loops through rows and formats them into the prettytable-rs format
        // I think this can be simplified down the line
        let mut sorted_rows = vec![];
        for row in &unsorted_rows {
            let mut values = vec![];
            for item in row {
                values.push(cell!(item));
            }
            sorted_rows.push(values)
        }

        for row in sorted_rows {
            table.add_row(Row::new(row));
        }
        cs_print_table!(table);
    }
}

fn save_hunt_results(dir: PathBuf, detections: &[Detection]) -> Result<()> {
    // Create a uniq list of all hunt result titles so that we can agg
    let detection_titles: &Vec<String> = &detections
        .iter()
        .map(|x| x.title.clone())
        .unique()
        .collect();
    // Create output directory
    create_dir_all(&dir)?;
    // Loop through uniq list of hunt results
    cs_println!();
    for title in detection_titles {
        let mut header = false;
        let mut unsorted_rows = vec![];
        // Build the final CSV filename
        // TODO: This feels very hacky, maybe we shouldn't use the title for the filename in this way?
        let mut filename = format!("{}.csv", title.replace(" ", "_").to_lowercase());
        if let Some(x) = filename.split('-').last() {
            filename = x.to_string();
            if &filename[0..1] == "_" {
                filename.remove(0);
            }
        }
        let path = dir.join(&filename);
        let mut writer = csv::Writer::from_path(path)?;
        for detection in detections {
            // Only group together results of the same hunt
            if detection.title != *title {
                continue;
            }
            if !header {
                // Write headers to CSV
                cs_eprintln!("[+] Created {}", filename);
                writer.write_record(&detection.headers)?;
                header = true;
            }
            // Values builder
            let mut values = vec![];
            for c in &detection.values {
                values.push(c);
            }
            unsorted_rows.push(values);
            // Write values to CSV
        }
        unsorted_rows.sort_by(|a, b| a.first().cmp(&b.first()));

        let mut sorted_rows = vec![];
        for row in &unsorted_rows {
            let mut values = vec![];
            for item in row {
                values.push(item);
            }
            sorted_rows.push(values)
        }

        for row in sorted_rows {
            writer.write_record(row)?;
        }
        writer.flush()?;
    }
    Ok(())
}

pub fn get_mapping_file(path: &Path) -> Result<Mapping> {
    let mapping: Mapping;
    let md = metadata(&path)?;
    if md.is_dir() {
        return Err(anyhow!(
            "Specified mapping file is a directory: '{}' - please specify a file",
            path.display()
        ));
    };
    match File::open(&path) {
        Ok(mut file) => {
            let mut content = String::new();
            file.read_to_string(&mut content)?;

            match serde_yaml::from_str(&content) {
                Ok(map) => mapping = map,
                Err(error) => return Err(anyhow!("Error in {}: {}", path.display(), error)),
            };
        }
        Err(error) => {
            return Err(anyhow!(
                "Failed to load mapping file from {}: {}",
                path.display(),
                error
            ));
        }
    }
    match RuleType::from(&mapping.kind) {
        Some(RuleType::Sigma) => {}
        Some(RuleType::Stalker) => {}
        None => {
            return Err(anyhow!(
    "Error in mapping file: '{}' is not a valid kind. 'stalker' or 'sigma' are supported options",
    mapping.kind
      ))
        }
    }
    Ok(mapping)
}

pub fn load_detection_rules(
    path: &Path,
    check: bool,
    mapping: &Mapping,
    verbose: bool,
) -> Result<Vec<ChainsawRule>> {
    let mut count = 0;
    let mut failed = 0;
    let mut chainsaw_rules: Vec<ChainsawRule> = Vec::new();
    if path.exists() {
        let md = metadata(&path)?;
        if md.is_dir() {
            // Grab all YML files from within the specified directory
            let mut rule_files = Vec::new();
            for file in WalkDir::new(path) {
                let file_a = file?;
                if let Some(x) = file_a.path().extension() {
                    if x == "yml" || x == "yaml" {
                        rule_files.push(file_a.into_path());
                    }
                }
            }
            match RuleType::from(&mapping.kind) {
                // Loop through yml files and confirm they're TAU rules
                Some(RuleType::Sigma) => {
                    for path in rule_files {
                        let rules = match sigma::load(&path) {
                            Ok(rules) => rules,
                            Err(e) => {
                                failed += 1;
                                if check {
                                    let file_name = match path.to_string_lossy().split('/').last() {
                                        Some(e) => e.to_string(),
                                        None => path.display().to_string(),
                                    };
                                    if let Some(source) = e.source() {
                                        cs_eprintln!("[!] {:?}: {} - {}", file_name, e, source);
                                    } else {
                                        cs_eprintln!("[!] {:?}: {}", file_name, e);
                                    }
                                }
                                continue;
                            }
                        };
                        if verbose {
                            for rule in &rules {
                                println!(
                                    "{}",
                                    serde_yaml::to_string(&rule).expect("could not serialise")
                                );
                            }
                        }
                        for file in rules {
                            let rule: ChainsawRule = match serde_yaml::from_value(file) {
                                Ok(e) => e,
                                Err(e) => {
                                    failed += 1;
                                    if check {
                                        let file_name =
                                            match path.to_string_lossy().split('/').last() {
                                                Some(e) => e.to_string(),
                                                None => path.display().to_string(),
                                            };
                                        cs_eprintln!("[!] {:?}: {}", file_name, e);
                                    }
                                    continue;
                                }
                            };
                            // Remove rules that are excluded in the mapping file
                            if let Some(exclusion) = &mapping.exclusions {
                                if exclusion.contains(&rule.tag) {
                                    failed += 1;
                                    if check {
                                        let file_name =
                                            match path.to_string_lossy().split('/').last() {
                                                Some(e) => e.to_string(),
                                                None => path.display().to_string(),
                                            };
                                        cs_eprintln!(
                                            "[!] {:?} is excluded in mapping file",
                                            file_name
                                        );
                                    }
                                    continue;
                                };
                            };
                            chainsaw_rules.push(rule);
                            count += 1;
                        }
                    }
                }
                Some(RuleType::Stalker) => {
                    for path in rule_files {
                        let rule: ChainsawRule = match stalker::load(&path) {
                            Ok(e) => e,
                            Err(e) => {
                                failed += 1;
                                if check {
                                    let file_name = match path.to_string_lossy().split('/').last() {
                                        Some(e) => e.to_string(),
                                        None => path.display().to_string(),
                                    };
                                    cs_eprintln!("[!] {:?}: {}", file_name, e);
                                }
                                continue;
                            }
                        };
                        // Remove any < HIGH level rules
                        if let Some(level) = rule.level.clone() {
                            match level.as_str() {
                                "high" => {}
                                "critical" => {}
                                _ => continue,
                            };
                        }
                        // Remove non-stable rules
                        if let Some(status) = rule.status.clone() {
                            match status.as_str() {
                                "stable" => {}
                                _ => continue,
                            };
                        }
                        // Remove rules that are excluded in the mapping file
                        if let Some(exclusion) = &mapping.exclusions {
                            if exclusion.contains(&rule.tag) {
                                failed += 1;
                                if check {
                                    let file_name = match path.to_string_lossy().split('/').last() {
                                        Some(e) => e.to_string(),
                                        None => path.display().to_string(),
                                    };
                                    cs_eprintln!("[!] {:?} is excluded in mapping file", file_name);
                                }
                                continue;
                            };
                        };
                        chainsaw_rules.push(rule);
                        count += 1;
                    }
                }
                None => {
                    return Err(anyhow!(
                        "Error in mapping file: '{}' is not a valid rule kind",
                        mapping.kind
                    ))
                }
            }
        } else {
            return Err(anyhow!("Invalid input path: {}. The rule parameter requires a directory path containing detection rules", path.display()));
        }
    } else {
        return Err(anyhow!("Invalid input path: {}", path.display()));
    };
    if count == 0 && !check {
        return Err(anyhow!(
            "Rule directory specified, but no valid rules found!"
        ));
    }
    if failed > 0 {
        if check {
            cs_eprintln!();
        }
        cs_eprintln!(
            "[+] Loaded {} detection rules ({} were not loaded)",
            count,
            failed
        );
    } else {
        cs_eprintln!("[+] Loaded {} detection rules", count);
    }
    Ok(chainsaw_rules)
}
