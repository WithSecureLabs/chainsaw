use std::collections::HashSet;
use std::path::{Path, PathBuf};

use chrono::{Local, NaiveDateTime, TimeZone, Utc};
use chrono_tz::Tz;
use serde::Serialize;

use crate::file::evtx::Parser as EvtxParser;
use crate::get_files;

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GapKind {
    RecordId,
    Timestamp,
}

#[derive(Debug, Serialize)]
pub struct Gap {
    pub kind: GapKind,
    pub channel: String,
    pub from: u64,
    pub until: u64,
    pub start: i64,
    pub stop: i64,
}

#[derive(Debug, Serialize)]
pub struct ChannelStats {
    pub channel: String,
    pub records_seen: u64,
    pub first_record_id: u64,
    pub last_record_id: u64,
    pub first_seconds: i64,
    pub last_seconds: i64,
}

#[derive(Debug, Serialize)]
pub struct FileGapReport {
    pub path: PathBuf,
    pub channels: Vec<ChannelStats>,
    pub gaps: Vec<Gap>,
}

pub struct GapAnalyser {
    paths: Vec<PathBuf>,
    min_time_gap_seconds: i64,
    detect_record_id_gaps: bool,
    detect_time_gaps: bool,
    skip_errors: bool,
    from: Option<NaiveDateTime>,
    to: Option<NaiveDateTime>,
}

impl GapAnalyser {
    pub fn new(
        paths: Vec<PathBuf>,
        min_time_gap_seconds: i64,
        detect_record_id_gaps: bool,
        detect_time_gaps: bool,
        skip_errors: bool,
        from: Option<NaiveDateTime>,
        to: Option<NaiveDateTime>,
    ) -> Self {
        Self {
            paths,
            min_time_gap_seconds,
            detect_record_id_gaps,
            detect_time_gaps,
            skip_errors,
            from,
            to,
        }
    }

    pub fn analyse(&self) -> crate::Result<Vec<FileGapReport>> {
        let evtx_exts: HashSet<String> = HashSet::from_iter(["evtx".to_string()]);
        let mut files = Vec::new();
        for path in &self.paths {
            let found = get_files(path, &Some(evtx_exts.clone()), self.skip_errors)?;
            files.extend(found);
        }
        if files.is_empty() {
            anyhow::bail!("No .evtx files found in the provided paths");
        }
        cs_eprintln!("[+] Analysing {} evtx file(s) for gaps", files.len());

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

    fn analyse_file(&self, path: &Path) -> crate::Result<FileGapReport> {
        let mut parser = EvtxParser::load(path)?;
        let from_secs = self.from.map(|d| d.and_utc().timestamp());
        let to_secs = self.to.map(|d| d.and_utc().timestamp());

        let mut entries: Vec<(String, u64, i64)> = Vec::new();

        for result in parser.parse() {
            match result {
                Ok(rec) => {
                    let secs = rec.timestamp.as_second();
                    if let Some(f) = from_secs
                        && secs < f
                    {
                        continue;
                    }
                    if let Some(t) = to_secs
                        && secs > t
                    {
                        continue;
                    }
                    let channel = rec
                        .data
                        .get("Event")
                        .and_then(|e| e.get("System"))
                        .and_then(|s| s.get("Channel"))
                        .and_then(|c| c.as_str())
                        .unwrap_or("<unknown>")
                        .to_string();
                    entries.push((channel, rec.event_record_id, secs));
                }
                Err(e) => {
                    if self.skip_errors {
                        cs_eyellowln!(
                            "[!] failed to parse record in '{}' - {}",
                            path.display(),
                            e
                        );
                        continue;
                    }
                    return Err(e.into());
                }
            }
        }

        entries.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        Ok(build_report(
            path.to_path_buf(),
            &entries,
            self.min_time_gap_seconds,
            self.detect_record_id_gaps,
            self.detect_time_gaps,
        ))
    }
}

fn build_report(
    path: PathBuf,
    entries: &[(String, u64, i64)],
    min_time_gap_seconds: i64,
    detect_record_id_gaps: bool,
    detect_time_gaps: bool,
) -> FileGapReport {
    let mut channels = Vec::new();
    let mut gaps = Vec::new();

    let mut i = 0;
    while i < entries.len() {
        let mut j = i + 1;
        while j < entries.len() && entries[j].0 == entries[i].0 {
            j += 1;
        }
        let slice = &entries[i..j];
        let channel = &slice[0].0;
        channels.push(ChannelStats {
            channel: channel.clone(),
            records_seen: slice.len() as u64,
            first_record_id: slice[0].1,
            last_record_id: slice[slice.len() - 1].1,
            first_seconds: slice[0].2,
            last_seconds: slice[slice.len() - 1].2,
        });
        for pair in slice.windows(2) {
            let (_, a_id, a_secs) = &pair[0];
            let (_, b_id, b_secs) = &pair[1];
            if detect_record_id_gaps && *b_id > a_id + 1 {
                gaps.push(Gap {
                    kind: GapKind::RecordId,
                    channel: channel.clone(),
                    from: *a_id,
                    until: *b_id,
                    start: *a_secs,
                    stop: *b_secs,
                });
            }
            if detect_time_gaps && b_secs - a_secs >= min_time_gap_seconds {
                gaps.push(Gap {
                    kind: GapKind::Timestamp,
                    channel: channel.clone(),
                    from: *a_id,
                    until: *b_id,
                    start: *a_secs,
                    stop: *b_secs,
                });
            }
        }
        i = j;
    }

    FileGapReport {
        path,
        channels,
        gaps,
    }
}

pub fn print_text_report(reports: &[FileGapReport], local: bool, timezone: Option<Tz>) {
    let format = TimeFormat { local, timezone };
    let mut total_id_gaps = 0u64;
    let mut total_time_gaps = 0u64;

    for report in reports {
        cs_println!("\n=== {} ===", report.path.display());
        cs_println!("[+] Channels seen:");
        for ch in &report.channels {
            cs_println!(
                "    - {}: {} records, RecordID {}..{}, {} -> {}",
                ch.channel,
                ch.records_seen,
                ch.first_record_id,
                ch.last_record_id,
                format.render(ch.first_seconds),
                format.render(ch.last_seconds),
            );
        }

        let id_gaps: Vec<&Gap> = report
            .gaps
            .iter()
            .filter(|g| g.kind == GapKind::RecordId)
            .collect();
        if id_gaps.is_empty() {
            cs_println!("[+] No RecordID gaps detected");
        } else {
            cs_println!(
                "[!] {} RecordID gap(s) detected (possible selective record deletion):",
                id_gaps.len()
            );
            for g in &id_gaps {
                cs_println!(
                    "    - {}: RecordID {} -> {} ({} missing) between {} and {}",
                    g.channel,
                    g.from,
                    g.until,
                    g.until - g.from - 1,
                    format.render(g.start),
                    format.render(g.stop),
                );
            }
            total_id_gaps += id_gaps.len() as u64;
        }

        let time_gaps: Vec<&Gap> = report
            .gaps
            .iter()
            .filter(|g| g.kind == GapKind::Timestamp)
            .collect();
        if time_gaps.is_empty() {
            cs_println!("[+] No suspicious time gaps detected");
        } else {
            cs_println!(
                "[!] {} time gap(s) exceeding threshold:",
                time_gaps.len()
            );
            for g in &time_gaps {
                cs_println!(
                    "    - {}: {} -> {} ({}s, RecordIDs {} -> {})",
                    g.channel,
                    format.render(g.start),
                    format.render(g.stop),
                    g.stop - g.start,
                    g.from,
                    g.until,
                );
            }
            total_time_gaps += time_gaps.len() as u64;
        }
    }

    cs_eprintln!(
        "\n[+] Done. {} RecordID gap(s), {} time gap(s) across {} file(s).",
        total_id_gaps,
        total_time_gaps,
        reports.len()
    );
}

struct TimeFormat {
    local: bool,
    timezone: Option<Tz>,
}

impl TimeFormat {
    fn render(&self, seconds: i64) -> String {
        let utc = Utc
            .timestamp_opt(seconds, 0)
            .single()
            .unwrap_or_else(|| Utc.timestamp_opt(0, 0).unwrap());
        if let Some(tz) = self.timezone {
            utc.with_timezone(&tz).to_rfc3339()
        } else if self.local {
            utc.with_timezone(&Local).to_rfc3339()
        } else {
            utc.to_rfc3339()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(channel: &str, id: u64, secs: i64) -> (String, u64, i64) {
        (channel.to_string(), id, secs)
    }

    fn sorted(mut v: Vec<(String, u64, i64)>) -> Vec<(String, u64, i64)> {
        v.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        v
    }

    #[test]
    fn detects_record_id_gap() {
        let entries = sorted(vec![
            entry("Security", 1, 0),
            entry("Security", 2, 10),
            entry("Security", 7, 20),
        ]);
        let report = build_report(PathBuf::from("test.evtx"), &entries, 60, true, true);

        let id_gaps: Vec<&Gap> = report
            .gaps
            .iter()
            .filter(|g| g.kind == GapKind::RecordId)
            .collect();
        assert_eq!(id_gaps.len(), 1);
        assert_eq!(id_gaps[0].channel, "Security");
        assert_eq!(id_gaps[0].from, 2);
        assert_eq!(id_gaps[0].until, 7);
    }

    #[test]
    fn detects_time_gap_above_threshold() {
        let entries = sorted(vec![
            entry("Security", 1, 0),
            entry("Security", 2, 30),
            entry("Security", 3, 200),
        ]);
        let report = build_report(PathBuf::from("test.evtx"), &entries, 60, true, true);

        let time_gaps: Vec<&Gap> = report
            .gaps
            .iter()
            .filter(|g| g.kind == GapKind::Timestamp)
            .collect();
        assert_eq!(time_gaps.len(), 1);
        assert_eq!(time_gaps[0].stop - time_gaps[0].start, 170);
        assert_eq!(time_gaps[0].from, 2);
    }

    #[test]
    fn ignores_clean_sequence() {
        let entries = sorted(vec![
            entry("Security", 1, 0),
            entry("Security", 2, 10),
            entry("Security", 3, 20),
        ]);
        let report = build_report(PathBuf::from("test.evtx"), &entries, 60, true, true);
        assert!(report.gaps.is_empty());
        assert_eq!(report.channels.len(), 1);
        assert_eq!(report.channels[0].records_seen, 3);
    }

    #[test]
    fn separates_gaps_per_channel() {
        let entries = sorted(vec![
            entry("Security", 1, 0),
            entry("Security", 2, 10),
            entry("Microsoft-Windows-Sysmon/Operational", 100, 0),
            entry("Microsoft-Windows-Sysmon/Operational", 150, 10),
        ]);
        let report = build_report(PathBuf::from("test.evtx"), &entries, 60, true, true);

        let id_gaps: Vec<&Gap> = report
            .gaps
            .iter()
            .filter(|g| g.kind == GapKind::RecordId)
            .collect();
        assert_eq!(id_gaps.len(), 1);
        assert_eq!(id_gaps[0].channel, "Microsoft-Windows-Sysmon/Operational");
    }

    #[test]
    fn flags_disabled_skip_their_category() {
        let entries = sorted(vec![entry("Security", 1, 0), entry("Security", 5, 600)]);

        let report = build_report(PathBuf::from("test.evtx"), &entries, 60, false, true);
        assert_eq!(report.gaps.len(), 1);
        assert!(report.gaps.iter().all(|g| g.kind == GapKind::Timestamp));

        let report = build_report(PathBuf::from("test.evtx"), &entries, 60, true, false);
        assert_eq!(report.gaps.len(), 1);
        assert!(report.gaps.iter().all(|g| g.kind == GapKind::RecordId));
    }
}
