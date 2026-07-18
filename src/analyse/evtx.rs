use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::file::evtx::Parser as EvtxParser;
use crate::get_files;

#[derive(Debug, Serialize)]
pub struct EventIdCount {
    pub event_id: u64,
    pub count: u64,
}

#[derive(Debug, Serialize)]
pub struct ChannelEventIdStats {
    pub channel: String,
    pub records_seen: u64,
    pub event_ids: Vec<EventIdCount>,
}

#[derive(Debug, Serialize)]
pub struct FileEvtxStats {
    pub path: PathBuf,
    pub records_seen: u64,
    pub channels: Vec<ChannelEventIdStats>,
}

pub struct EvtxAnalyser {
    paths: Vec<PathBuf>,
    skip_errors: bool,
}

impl EvtxAnalyser {
    pub fn new(paths: Vec<PathBuf>, skip_errors: bool) -> Self {
        Self { paths, skip_errors }
    }

    pub fn analyse(&self) -> crate::Result<Vec<FileEvtxStats>> {
        let evtx_exts: HashSet<String> = HashSet::from_iter(["evtx".to_string()]);
        let mut files = Vec::new();
        for path in &self.paths {
            let found = get_files(path, &Some(evtx_exts.clone()), self.skip_errors)?;
            files.extend(found);
        }
        if files.is_empty() {
            anyhow::bail!("No .evtx files found in the provided paths");
        }
        cs_eprintln!(
            "[+] Analysing {} evtx file(s) for summary statistics",
            files.len()
        );

        let mut reports = Vec::new();
        for file in &files {
            match self.analyse_file(file) {
                Ok(report) => reports.push(report),
                Err(e) => {
                    if self.skip_errors {
                        cs_eyellowln!("[!] failed to analyse '{}' - {}", file.display(), e);
                    } else {
                        return Err(e);
                    }
                }
            }
        }
        Ok(reports)
    }

    fn analyse_file(&self, path: &Path) -> crate::Result<FileEvtxStats> {
        let mut parser = EvtxParser::load(path)?;

        let mut entries: Vec<(String, u64)> = Vec::new();

        for result in parser.parse() {
            match result {
                Ok(rec) => {
                    let system = rec.data.get("Event").and_then(|e| e.get("System"));
                    let channel = system
                        .and_then(|s| s.get("Channel"))
                        .and_then(|c| c.as_str())
                        .unwrap_or("<unknown>")
                        .to_string();
                    let event_id = match system.and_then(|s| s.get("EventID")) {
                        Some(v) => extract_event_id(v),
                        None => None,
                    };
                    if let Some(id) = event_id {
                        entries.push((channel, id));
                    }
                }
                Err(e) => {
                    if self.skip_errors {
                        cs_eyellowln!("[!] failed to parse record in '{}' - {}", path.display(), e);
                        continue;
                    }
                    return Err(e.into());
                }
            }
        }

        Ok(build_report(path.to_path_buf(), &entries))
    }
}

fn extract_event_id(value: &serde_json::Value) -> Option<u64> {
    if let Some(n) = value.as_u64() {
        return Some(n);
    }
    if let Some(s) = value.as_str() {
        return s.parse::<u64>().ok();
    }
    if let Some(obj) = value.as_object()
        && let Some(text) = obj.get("#text")
    {
        return extract_event_id(text);
    }
    None
}

fn build_report(path: PathBuf, entries: &[(String, u64)]) -> FileEvtxStats {
    let mut by_channel: BTreeMap<&str, BTreeMap<u64, u64>> = BTreeMap::new();
    for (channel, event_id) in entries {
        let inner = by_channel.entry(channel.as_str()).or_default();
        *inner.entry(*event_id).or_insert(0) += 1;
    }

    let channels: Vec<ChannelEventIdStats> = by_channel
        .into_iter()
        .map(|(channel, ids)| {
            let event_ids: Vec<EventIdCount> = ids
                .into_iter()
                .map(|(event_id, count)| EventIdCount { event_id, count })
                .collect();
            let records_seen = event_ids.iter().map(|e| e.count).sum();
            ChannelEventIdStats {
                channel: channel.to_string(),
                records_seen,
                event_ids,
            }
        })
        .collect();

    let records_seen = channels.iter().map(|c| c.records_seen).sum();

    FileEvtxStats {
        path,
        records_seen,
        channels,
    }
}

pub fn print_text_report(reports: &[FileEvtxStats]) {
    let mut total_records = 0u64;

    for report in reports {
        cs_println!("\n=== {} ===", report.path.display());
        cs_println!("[+] Total records: {}", report.records_seen);
        for channel in &report.channels {
            cs_println!("[+] {} ({} records)", channel.channel, channel.records_seen);
            cs_println!("    Event ID    Count");
            for entry in &channel.event_ids {
                cs_println!("    {:<11} {}", entry.event_id, entry.count);
            }
        }
        total_records += report.records_seen;
    }

    cs_eprintln!(
        "\n[+] Done. {} record(s) across {} file(s).",
        total_records,
        reports.len()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(channel: &str, event_id: u64) -> (String, u64) {
        (channel.to_string(), event_id)
    }

    #[test]
    fn counts_event_ids_per_channel() {
        let entries = vec![
            entry("Security", 4624),
            entry("Security", 4624),
            entry("Security", 4625),
            entry("Microsoft-Windows-Sysmon/Operational", 1),
            entry("Microsoft-Windows-Sysmon/Operational", 1),
            entry("Microsoft-Windows-Sysmon/Operational", 3),
        ];
        let report = build_report(PathBuf::from("test.evtx"), &entries);

        assert_eq!(report.records_seen, 6);
        assert_eq!(report.channels.len(), 2);

        let security = report
            .channels
            .iter()
            .find(|c| c.channel == "Security")
            .unwrap();
        assert_eq!(security.records_seen, 3);
        assert_eq!(security.event_ids.len(), 2);
        let id_4624 = security
            .event_ids
            .iter()
            .find(|e| e.event_id == 4624)
            .unwrap();
        assert_eq!(id_4624.count, 2);

        let sysmon = report
            .channels
            .iter()
            .find(|c| c.channel == "Microsoft-Windows-Sysmon/Operational")
            .unwrap();
        assert_eq!(sysmon.records_seen, 3);
        assert_eq!(sysmon.event_ids.len(), 2);
    }

    #[test]
    fn event_ids_within_channel_are_sorted_ascending() {
        let entries = vec![
            entry("Security", 4625),
            entry("Security", 4624),
            entry("Security", 4634),
        ];
        let report = build_report(PathBuf::from("test.evtx"), &entries);
        let ids: Vec<u64> = report.channels[0]
            .event_ids
            .iter()
            .map(|e| e.event_id)
            .collect();
        assert_eq!(ids, vec![4624, 4625, 4634]);
    }

    #[test]
    fn empty_input_produces_empty_report() {
        let report = build_report(PathBuf::from("test.evtx"), &[]);
        assert_eq!(report.records_seen, 0);
        assert!(report.channels.is_empty());
    }

    #[test]
    fn extract_event_id_handles_number_string_and_text_object() {
        assert_eq!(extract_event_id(&serde_json::json!(4624)), Some(4624));
        assert_eq!(extract_event_id(&serde_json::json!("4624")), Some(4624));
        assert_eq!(
            extract_event_id(&serde_json::json!({"#text": 4624})),
            Some(4624)
        );
        assert_eq!(extract_event_id(&serde_json::json!(null)), None);
        assert_eq!(extract_event_id(&serde_json::json!("not-a-number")), None);
    }
}
