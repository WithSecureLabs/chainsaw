use std::fs::File;
use std::path::PathBuf;

use anyhow::Result;
use chrono::NaiveDateTime;
use evtx::{EvtxParser, ParserSettings};
use regex::Regex;
use structopt::StructOpt;

use crate::util::get_evtx_files;

#[derive(StructOpt)]
pub struct SearchOpts {
    /// Specify an EVTX file, or a directory containing the EVTX files to search.
    /// If you specify a directory, all files matching *.evtx will be used.
    pub evtx_path: PathBuf,

    /// Suppress all unnecessary output
    #[structopt(short = "q", long = "quiet")]
    pub quiet: bool,

    /// This option can be used in conjunction with any other search methods. It will only return
    /// results of the event ID supplied.
    #[structopt(short = "e", long = "event")]
    pub event_id: Option<u32>,

    /// Use this option to search EVTx files for the string supplied. If the string is found, the
    /// whole matching event will be returned.
    /// Use the -i flag for case insensitive searches.
    #[structopt(short = "s", long = "string")]
    pub search_string: Option<String>,

    /// Skip EVTX file if chainsaw is unable to parse the records
    #[structopt(long = "ignore-errors")]
    pub ignore: bool,

    /// Set search to case insensitive. Usable only with string searching.
    #[structopt(short = "i", long = "case-insensitive")]
    pub case_insensitive: bool,

    /// Save the full event log and associated detections to disk in a JSON format to the specified path
    #[structopt(short, long = "json", group = "output")]
    pub json: bool,

    /// Use this option to search EVTx files for the regex pattern supplied. If a pattern match is found, the
    /// whole matching event will be returned.
    #[structopt(short = "r", long = "regex-search")]
    pub search_regex: Option<String>,

    /// Start date for including events (UTC). Anything older than this is dropped. Format: YYYY-MM-DDTHH:MM:SS. Example: 2019-11-17T17:55:11
    #[structopt(long = "start-date")]
    pub start_date: Option<String>,

    /// End date for including events (UTC). Anything newer than this is dropped. Format: YYYY-MM-DDTHH:MM:SS. Example: 2019-11-17T17:55:11
    #[structopt(long = "end-date")]
    pub end_date: Option<String>,
}

pub fn run_search(opt: SearchOpts) -> Result<String> {
    // Load EVTX Files
    let evtx_files = get_evtx_files(&opt.evtx_path)?;
    if opt.json {
        cs_print!("[");
    }

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

    // Loop through EVTX files and perform actions
    let mut hits = 0;
    cs_eprintln!("[+] Searching event logs...");
    for evtx in &evtx_files {
        // Parse EVTx files
        let settings = ParserSettings::default().num_threads(0);
        let parser = match EvtxParser::from_path(evtx) {
            Ok(a) => a.with_configuration(settings),
            Err(e) => {
                if opt.ignore {
                    continue;
                }
                return Err(anyhow!("{:?} - {}", evtx, e));
            }
        };

        // Search EVTX files for user supplied arguments
        hits += search_evtx_file(parser, &opt, hits == 0, sd_marker, ed_marker)?;
    }
    if opt.json {
        cs_println!("]");
    }
    Ok(format!("\n[+] Found {} matching log entries", hits))
}

pub fn search_evtx_file(
    mut parser: EvtxParser<File>,
    opt: &SearchOpts,
    first: bool,
    sd_marker: Option<NaiveDateTime>,
    ed_marker: Option<NaiveDateTime>,
) -> Result<usize> {
    let mut hits = 0;

    for record in parser.records_json_value() {
        // TODO - work out why chunks of a record can fail here, but the overall event logs count
        // isn't affected. If this parser isn't seeing an event that you know exists, it's mostly
        // likely due to this match block
        let r = match record {
            Ok(record) => record,
            Err(_) => {
                continue;
            }
        };

        // Perform start/end datetime filtering
        if sd_marker.is_some() || ed_marker.is_some() {
            let event_time = match NaiveDateTime::parse_from_str(
                r.data["Event"]["System"]["TimeCreated"]["#attributes"]["SystemTime"]
                    .as_str()
                    .unwrap(),
                "%Y-%m-%dT%H:%M:%S%.6fZ",
            ) {
                Ok(t) => t,
                Err(_) => {
                    return Err(anyhow!(
                        "Failed to parse datetime from supplied events. This shouldn't happen..."
                    ));
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
        // Do processing of EVTX record now it's in a JSON format
        //
        // The default action of the whole OK logic block it mark a record as matched
        // If a filter criteria is NOT matched, then we contiue the loop and don't push the
        // Record onto the matched records array

        // EventIDs can be stored in two different locations
        let event_id;
        if r.data["Event"]["System"]["EventID"]["#text"].is_null() {
            event_id = &r.data["Event"]["System"]["EventID"];
        } else {
            event_id = &r.data["Event"]["System"]["EventID"]["#text"];
        }

        // Handle event_id search option
        if let Some(e_id) = opt.event_id {
            if event_id != e_id {
                continue;
            }
        };
        // Handle string search option
        if let Some(string) = &opt.search_string {
            if opt.case_insensitive {
                // Case insensitive string search
                if !r
                    .data
                    .to_string()
                    .to_lowercase()
                    .contains(&string.to_lowercase())
                {
                    continue;
                }
            } else {
                // Case sensitive search
                if !r.data.to_string().contains(string) {
                    continue;
                }
            }
        };

        // Handle regex search option
        if let Some(reg) = &opt.search_regex {
            let re = Regex::new(reg)?;
            if !re.is_match(&r.data.to_string()) {
                continue;
            }
        }

        if opt.json {
            if !(first && hits == 0) {
                cs_print!(",");
            }
            cs_print_json!(&r.data)?;
        } else {
            cs_print_yaml!(&r.data)?;
        }

        hits += 1;
    }
    Ok(hits)
}
