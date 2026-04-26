use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::file::evtx::Parser as EvtxParser;
use crate::get_files;

#[derive(Debug, Serialize)]
pub struct ChannelStats {
    pub channel: String,
    pub records_seen: u64,
    pub first_record_id: u64,
    pub last_record_id: u64,
    pub first_timestamp: String,
    pub last_timestamp: String,
}

#[derive(Debug, Serialize)]
pub struct RecordIdGap {
    pub channel: String,
    pub prev_record_id: u64,
    pub next_record_id: u64,
    pub missing_records: u64,
    pub prev_timestamp: String,
    pub next_timestamp: String,
}

#[derive(Debug, Serialize)]
pub struct TimeGap {
    pub channel: String,
    pub prev_record_id: u64,
    pub next_record_id: u64,
    pub prev_timestamp: String,
    pub next_timestamp: String,
    pub gap_seconds: i64,
}

#[derive(Debug, Serialize)]
pub struct FileGapReport {
    pub path: PathBuf,
    pub channels: Vec<ChannelStats>,
    pub record_id_gaps: Vec<RecordIdGap>,
    pub time_gaps: Vec<TimeGap>,
}

pub struct GapAnalyser {
    paths: Vec<PathBuf>,
    min_time_gap_seconds: i64,
    detect_record_id_gaps: bool,
    detect_time_gaps: bool,
    skip_errors: bool,
}

impl GapAnalyser {
    pub fn new(
        paths: Vec<PathBuf>,
        min_time_gap_seconds: i64,
        detect_record_id_gaps: bool,
        detect_time_gaps: bool,
        skip_errors: bool,
    ) -> Self {
        Self {
            paths,
            min_time_gap_seconds,
            detect_record_id_gaps,
            detect_time_gaps,
            skip_errors,
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

        // channel -> Vec<(record_id, ts_string, ts_seconds)>
        let mut by_channel: BTreeMap<String, Vec<(u64, String, i64)>> = BTreeMap::new();

        for result in parser.parse() {
            match result {
                Ok(rec) => {
                    let channel = rec
                        .data
                        .get("Event")
                        .and_then(|e| e.get("System"))
                        .and_then(|s| s.get("Channel"))
                        .and_then(|c| c.as_str())
                        .unwrap_or("<unknown>")
                        .to_string();
                    let ts = rec.timestamp;
                    by_channel.entry(channel).or_default().push((
                        rec.event_record_id,
                        ts.to_string(),
                        ts.as_second(),
                    ));
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

        Ok(build_report(
            path.to_path_buf(),
            by_channel,
            self.min_time_gap_seconds,
            self.detect_record_id_gaps,
            self.detect_time_gaps,
        ))
    }
}

fn build_report(
    path: PathBuf,
    by_channel: BTreeMap<String, Vec<(u64, String, i64)>>,
    min_time_gap_seconds: i64,
    detect_record_id_gaps: bool,
    detect_time_gaps: bool,
) -> FileGapReport {
    let mut channel_stats = Vec::new();
    let mut record_id_gaps = Vec::new();
    let mut time_gaps = Vec::new();

    for (channel, mut entries) in by_channel {
        entries.sort_by_key(|(id, _, _)| *id);
        if entries.is_empty() {
            continue;
        }
        let first = &entries[0];
        let last = entries.last().expect("non-empty");
        channel_stats.push(ChannelStats {
            channel: channel.clone(),
            records_seen: entries.len() as u64,
            first_record_id: first.0,
            last_record_id: last.0,
            first_timestamp: first.1.clone(),
            last_timestamp: last.1.clone(),
        });

        for pair in entries.windows(2) {
            let (a_id, ref a_ts, a_secs) = pair[0];
            let (b_id, ref b_ts, b_secs) = pair[1];

            if detect_record_id_gaps && b_id > a_id + 1 {
                record_id_gaps.push(RecordIdGap {
                    channel: channel.clone(),
                    prev_record_id: a_id,
                    next_record_id: b_id,
                    missing_records: b_id - a_id - 1,
                    prev_timestamp: a_ts.clone(),
                    next_timestamp: b_ts.clone(),
                });
            }

            if detect_time_gaps {
                let gap_secs = b_secs - a_secs;
                if gap_secs >= min_time_gap_seconds {
                    time_gaps.push(TimeGap {
                        channel: channel.clone(),
                        prev_record_id: a_id,
                        next_record_id: b_id,
                        prev_timestamp: a_ts.clone(),
                        next_timestamp: b_ts.clone(),
                        gap_seconds: gap_secs,
                    });
                }
            }
        }
    }

    FileGapReport {
        path,
        channels: channel_stats,
        record_id_gaps,
        time_gaps,
    }
}

pub fn print_text_report(reports: &[FileGapReport]) {
    use std::fmt::Write as _;

    let mut buf = String::new();
    let mut total_id_gaps = 0u64;
    let mut total_time_gaps = 0u64;

    for report in reports {
        let _ = writeln!(buf, "\n=== {} ===", report.path.display());
        let _ = writeln!(buf, "[+] Channels seen:");
        for ch in &report.channels {
            let _ = writeln!(
                buf,
                "    - {}: {} records, RecordID {}..{}, {} -> {}",
                ch.channel,
                ch.records_seen,
                ch.first_record_id,
                ch.last_record_id,
                ch.first_timestamp,
                ch.last_timestamp
            );
        }
        if report.record_id_gaps.is_empty() {
            let _ = writeln!(buf, "[+] No RecordID gaps detected");
        } else {
            let _ = writeln!(
                buf,
                "[!] {} RecordID gap(s) detected (possible selective record deletion):",
                report.record_id_gaps.len()
            );
            for g in &report.record_id_gaps {
                let _ = writeln!(
                    buf,
                    "    - {}: RecordID {} -> {} ({} missing) between {} and {}",
                    g.channel,
                    g.prev_record_id,
                    g.next_record_id,
                    g.missing_records,
                    g.prev_timestamp,
                    g.next_timestamp
                );
            }
            total_id_gaps += report.record_id_gaps.len() as u64;
        }
        if report.time_gaps.is_empty() {
            let _ = writeln!(buf, "[+] No suspicious time gaps detected");
        } else {
            let _ = writeln!(
                buf,
                "[!] {} time gap(s) exceeding threshold:",
                report.time_gaps.len()
            );
            for g in &report.time_gaps {
                let _ = writeln!(
                    buf,
                    "    - {}: {} -> {} ({}s, RecordIDs {} -> {})",
                    g.channel,
                    g.prev_timestamp,
                    g.next_timestamp,
                    g.gap_seconds,
                    g.prev_record_id,
                    g.next_record_id
                );
            }
            total_time_gaps += report.time_gaps.len() as u64;
        }
    }

    cs_print!("{}", buf);
    cs_eprintln!(
        "\n[+] Done. {} RecordID gap(s), {} time gap(s) across {} file(s).",
        total_id_gaps,
        total_time_gaps,
        reports.len()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: u64, secs: i64) -> (u64, String, i64) {
        (id, format!("ts({})", secs), secs)
    }

    #[test]
    fn detects_record_id_gap() {
        let mut by_channel = BTreeMap::new();
        by_channel.insert(
            "Security".to_string(),
            vec![entry(1, 0), entry(2, 10), entry(7, 20)],
        );
        let report = build_report(PathBuf::from("test.evtx"), by_channel, 60, true, true);

        assert_eq!(report.record_id_gaps.len(), 1);
        let g = &report.record_id_gaps[0];
        assert_eq!(g.channel, "Security");
        assert_eq!(g.prev_record_id, 2);
        assert_eq!(g.next_record_id, 7);
        assert_eq!(g.missing_records, 4);
    }

    #[test]
    fn detects_time_gap_above_threshold() {
        let mut by_channel = BTreeMap::new();
        by_channel.insert(
            "Security".to_string(),
            vec![entry(1, 0), entry(2, 30), entry(3, 200)],
        );
        let report = build_report(PathBuf::from("test.evtx"), by_channel, 60, true, true);

        assert_eq!(report.time_gaps.len(), 1);
        assert_eq!(report.time_gaps[0].gap_seconds, 170);
        assert_eq!(report.time_gaps[0].prev_record_id, 2);
    }

    #[test]
    fn ignores_clean_sequence() {
        let mut by_channel = BTreeMap::new();
        by_channel.insert(
            "Security".to_string(),
            vec![entry(1, 0), entry(2, 10), entry(3, 20)],
        );
        let report = build_report(PathBuf::from("test.evtx"), by_channel, 60, true, true);

        assert!(report.record_id_gaps.is_empty());
        assert!(report.time_gaps.is_empty());
        assert_eq!(report.channels.len(), 1);
        assert_eq!(report.channels[0].records_seen, 3);
    }

    #[test]
    fn separates_gaps_per_channel() {
        let mut by_channel = BTreeMap::new();
        by_channel.insert("Security".to_string(), vec![entry(1, 0), entry(2, 10)]);
        by_channel.insert(
            "Microsoft-Windows-Sysmon/Operational".to_string(),
            vec![entry(100, 0), entry(150, 10)],
        );
        let report = build_report(PathBuf::from("test.evtx"), by_channel, 60, true, true);

        assert_eq!(report.record_id_gaps.len(), 1);
        assert_eq!(
            report.record_id_gaps[0].channel,
            "Microsoft-Windows-Sysmon/Operational"
        );
    }

    #[test]
    fn flags_disabled_skip_their_category() {
        let mut by_channel = BTreeMap::new();
        by_channel.insert(
            "Security".to_string(),
            vec![entry(1, 0), entry(5, 600)], // both id-gap and time-gap
        );
        let report = build_report(PathBuf::from("test.evtx"), by_channel, 60, false, true);
        assert!(report.record_id_gaps.is_empty());
        assert_eq!(report.time_gaps.len(), 1);

        let mut by_channel = BTreeMap::new();
        by_channel.insert("Security".to_string(), vec![entry(1, 0), entry(5, 600)]);
        let report = build_report(PathBuf::from("test.evtx"), by_channel, 60, true, false);
        assert_eq!(report.record_id_gaps.len(), 1);
        assert!(report.time_gaps.is_empty());
    }
}
