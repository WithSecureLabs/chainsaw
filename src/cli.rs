use std::collections::{HashMap, HashSet};
use std::fs;

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use chrono_tz::Tz;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use prettytable::{cell, format, Row, Table};
use serde::Serialize;
use tau_engine::Document;
use uuid::Uuid;

use crate::file::Kind as FileKind;
use crate::hunt::{Detections, Group, Hunt, Kind, Mapper, Mapping};
use crate::rule::{
    chainsaw::{Level, Rule as Chainsaw, Status},
    Kind as RuleKind,
};
use crate::write::WRITER;

#[cfg(not(windows))]
pub const RULE_PREFIX: &str = "‣";

#[cfg(windows)]
pub const RULE_PREFIX: &str = "+";

#[cfg(not(windows))]
const TICK_SETTINGS: (&str, u64) = ("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏ ", 80);

#[cfg(windows)]
const TICK_SETTINGS: (&str, u64) = (r"-\|/-", 200);

pub fn init_progress_bar(size: u64, msg: String) -> indicatif::ProgressBar {
    let pb = ProgressBar::new(size);
    unsafe {
        match crate::write::WRITER.quiet {
            true => pb.set_draw_target(ProgressDrawTarget::hidden()),
            false => pb.set_draw_target(ProgressDrawTarget::stderr()),
        }
    };
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[+] {msg}: [{bar:40}] {pos}/{len} {spinner}")
            .tick_chars(TICK_SETTINGS.0)
            .progress_chars("=>-"),
    );

    pb.set_message(msg);
    pb.enable_steady_tick(TICK_SETTINGS.1);
    pb
}

pub fn format_field_length(data: &str, full_output: bool, length: u32) -> String {
    // Take the context_field and format it for printing. Remove newlines, break into even chunks etc.
    // If this is a scheduled task we need to parse the XML to make it more readable
    let mut data = data
        .replace("\n", "")
        .replace("\r", "")
        .replace("\t", "")
        .replace("  ", " ")
        .chars()
        .collect::<Vec<char>>()
        .chunks(length as usize)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<String>>()
        .join("\n");

    let truncate_len = 1000;

    if !full_output && data.len() > truncate_len {
        data.truncate(truncate_len);
        data.push_str("...\n\n(use --full to show all content)");
    }

    data
}

// FIXME: All the table stuff needs a little think due to the field complexities...

pub fn print_detections(
    detections: &[Detections],
    hunts: &[Hunt],
    mappings: &[Mapping],
    rules: &HashMap<RuleKind, Vec<(Uuid, Chainsaw)>>,
    column_width: u32,
    full: bool,
    local: bool,
    metadata: bool,
    timezone: Option<Tz>,
) {
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

    // Build headers
    let mut headers: HashMap<&String, (Vec<&String>, HashSet<&String>)> = HashMap::new();
    for hunt in hunts {
        let headers = headers
            .entry(&hunt.group)
            .or_insert((vec![], HashSet::new()));
        for header in &hunt.headers {
            if !headers.1.contains(&header) {
                (*headers).0.push(&header);
                (*headers).1.insert(&header);
            }
        }
    }
    // Build lookups
    let mut groups: HashMap<&Uuid, &Group> = HashMap::new();
    for mapping in mappings {
        for group in &mapping.groups {
            groups.insert(&group.id, group);
        }
    }
    let hunts: HashMap<_, _> = hunts.iter().map(|h| (&h.id, h)).collect();
    let rules: HashMap<_, _> = rules.values().flatten().map(|r| (&r.0, &r.1)).collect();

    // Do a single unfold... <Group, Vec<(Timestamp, Kind, Vec<(Hunt ID, Rule ID)>>>
    let mut grouped: HashMap<&String, Vec<(&NaiveDateTime, &Kind, Vec<(&Uuid, &Uuid)>)>> =
        HashMap::new();
    for detection in detections {
        let mut tags: HashMap<&String, (&NaiveDateTime, Vec<(&Uuid, &Uuid)>)> = HashMap::new();
        for hit in &detection.hits {
            let group = &hunts.get(&hit.hunt).expect("could not get hunt").group;
            let tags = tags.entry(&group).or_insert((&hit.timestamp, vec![]));
            (*tags).1.push((&hit.hunt, &hit.rule));
        }
        for (k, v) in tags {
            let grouped = grouped.entry(k).or_insert(vec![]);
            (*grouped).push((&v.0, &detection.kind, v.1));
        }
    }

    let mut keys = grouped.keys().cloned().collect::<Vec<_>>();
    keys.sort();
    for key in keys {
        let mut grouped = grouped.remove(&key).expect("could not get grouped!");
        grouped.sort_by(|x, y| x.0.cmp(&y.0));
        let mut table = Table::new();
        table.set_format(format);
        if let Some((headers, _)) = headers.remove(key) {
            let mut cells = vec![
                cell!("timestamp").style_spec("c"),
                cell!("detections").style_spec("c"),
            ];
            if headers.is_empty() {
                cells.push(cell!("data").style_spec("c"));
            } else {
                for header in &headers {
                    cells.push(cell!(header).style_spec("c"));
                }
            }
            table.add_row(Row::new(cells));
            for (timestamp, kind, ids) in grouped {
                // FIXME: Sort rules
                //ids.sort();
                let localised = if let Some(timezone) = timezone {
                    timezone
                        .from_local_datetime(timestamp)
                        .single()
                        .expect("failed to localise timestamp")
                        .to_rfc3339()
                } else if local {
                    Utc.from_local_datetime(timestamp)
                        .single()
                        .expect("failed to localise timestamp")
                        .to_rfc3339()
                } else {
                    DateTime::<Utc>::from_utc(timestamp.clone(), Utc).to_rfc3339()
                };
                let mut cells = vec![cell!(localised)];
                if metadata {
                    let mut table = Table::new();
                    table.add_row(Row::new(vec![
                        cell!("name").style_spec("c"),
                        cell!("authors").style_spec("c"),
                        cell!("level").style_spec("c"),
                        cell!("status").style_spec("c"),
                    ]));
                    for (_, rid) in &ids {
                        let rule = rules.get(rid).expect("could not get rule");
                        table.add_row(Row::new(vec![
                            cell!(rule.name),
                            cell!(rule.authors.join("\n")),
                            cell!(rule.level),
                            cell!(rule.status),
                        ]));
                    }
                    cells.push(cell!(table));
                } else {
                    cells.push(cell!(ids
                        .iter()
                        .map(|(_, rid)| format!(
                            "{} {}",
                            RULE_PREFIX,
                            rules.get(rid).expect("could not get rule").name.as_str()
                        ))
                        .collect::<Vec<_>>()
                        .join("\n")));
                }
                let document = match kind {
                    Kind::Individual { document } => document,
                    Kind::Aggregate { documents } => {
                        documents.first().expect("could not get document")
                    }
                };
                if headers.is_empty() {
                    let json = serde_json::to_string(&document.data)
                        .expect("could not serialise document");
                    cells.push(cell!(format_field_length(&json, false, column_width)));
                } else {
                    // This is really complicated, we could land in the same group but be from
                    // different hunts that have different headers, that also could even overlap...
                    // Because we group we won't be able to reliably handle clashes.
                    let mut hids = HashSet::new();
                    for (hid, _) in &ids {
                        hids.insert(hid);
                    }
                    let wrapper = match &document.kind {
                        FileKind::Evtx => crate::evtx::Wrapper(&document.data),
                        _ => continue,
                    };
                    let mut hdrs = HashMap::new();
                    for hid in hids {
                        let hunt = hunts.get(hid).expect("could not get hunt");
                        let fields = match &hunt.kind {
                            crate::hunt::HuntKind::Group { .. } => {
                                &groups.get(&hunt.id).expect("could not get group").fields
                            }
                            crate::hunt::HuntKind::Rule { .. } => {
                                &rules.get(&hunt.id).expect("could not get rule").fields
                            }
                        };
                        let flds: HashMap<_, _> =
                            fields.iter().map(|f| (&f.name, &f.from)).collect();
                        for header in &headers {
                            if let Some(from) = flds.get(header) {
                                let mapper = Mapper(&hunt.mapper, &wrapper);
                                if let Some(value) = mapper.find(&from).and_then(|v| v.to_string())
                                {
                                    hdrs.insert(
                                        header,
                                        format_field_length(&value, full, column_width),
                                    );
                                }
                            }
                        }
                    }
                    for header in &headers {
                        if let Some(value) = hdrs.get(header) {
                            cells.push(cell!(value));
                        } else {
                            cells.push(cell!(""));
                        }
                    }
                }
                table.add_row(Row::new(cells));
            }
        }
        cs_greenln!("\n[+] Group: {}", key);
        cs_print_table!(table);
    }
}

pub fn print_csv(
    detections: &[Detections],
    hunts: &[Hunt],
    mappings: &[Mapping],
    rules: &HashMap<RuleKind, Vec<(Uuid, Chainsaw)>>,
    local: bool,
    timezone: Option<Tz>,
) -> crate::Result<()> {
    let directory = unsafe {
        WRITER
            .path
            .as_ref()
            .expect("could not get output directory")
    };
    fs::create_dir_all(directory)?;
    // Build headers
    let mut headers: HashMap<&String, (Vec<&String>, HashSet<&String>)> = HashMap::new();
    for hunt in hunts {
        let headers = headers
            .entry(&hunt.group)
            .or_insert((vec![], HashSet::new()));
        for header in &hunt.headers {
            if !headers.1.contains(&header) {
                (*headers).0.push(&header);
                (*headers).1.insert(&header);
            }
        }
    }
    // Build lookups
    let mut groups: HashMap<&Uuid, &Group> = HashMap::new();
    for mapping in mappings {
        for group in &mapping.groups {
            groups.insert(&group.id, group);
        }
    }
    let hunts: HashMap<_, _> = hunts.iter().map(|h| (&h.id, h)).collect();
    let rules: HashMap<_, _> = rules.values().flatten().map(|r| (&r.0, &r.1)).collect();
    // Do a single unfold...
    let mut grouped: HashMap<&String, Vec<(&NaiveDateTime, &Kind, Vec<(&Uuid, &Uuid)>)>> =
        HashMap::new();
    for detection in detections {
        let mut tags: HashMap<&String, (&NaiveDateTime, Vec<(&Uuid, &Uuid)>)> = HashMap::new();
        for hit in &detection.hits {
            let group = &hunts.get(&hit.hunt).expect("could not get hunt").group;
            let tags = tags.entry(&group).or_insert((&hit.timestamp, vec![]));
            (*tags).1.push((&hit.hunt, &hit.rule));
        }
        for (k, v) in tags {
            let grouped = grouped.entry(k).or_insert(vec![]);
            (*grouped).push((&v.0, &detection.kind, v.1));
        }
    }
    let mut keys = grouped.keys().cloned().collect::<Vec<_>>();
    keys.sort();
    for key in keys {
        let mut grouped = grouped.remove(&key).expect("could not get grouped!");
        grouped.sort_by(|x, y| x.0.cmp(&y.0));
        // FIXME: Handle name clashes
        let filename = format!("{}.csv", key.replace(" ", "_").to_lowercase());
        let path = directory.join(&filename);
        let mut csv = prettytable::csv::Writer::from_path(path)?;
        cs_eprintln!("[+] Created {}", filename);
        if let Some((headers, _)) = headers.remove(key) {
            let mut cells = vec!["timestamp", "detections"];
            if headers.is_empty() {
                cells.push("data");
            } else {
                for header in &headers {
                    cells.push(header);
                }
            }
            csv.write_record(cells)?;
            for (timestamp, kind, ids) in grouped {
                // FIXME: Sort tags
                //tags.sort();
                let localised = if let Some(timezone) = timezone {
                    timezone
                        .from_local_datetime(timestamp)
                        .single()
                        .expect("failed to localise timestamp")
                        .to_rfc3339()
                } else if local {
                    Utc.from_local_datetime(timestamp)
                        .single()
                        .expect("failed to localise timestamp")
                        .to_rfc3339()
                } else {
                    DateTime::<Utc>::from_utc(timestamp.clone(), Utc).to_rfc3339()
                };
                let mut cells = vec![localised];
                cells.push(
                    ids.iter()
                        .map(|(_, rid)| {
                            format!(
                                "{}",
                                rules.get(rid).expect("could not get rule").name.as_str()
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(";"),
                );
                let document = match kind {
                    Kind::Individual { document } => document,
                    Kind::Aggregate { documents } => {
                        documents.first().expect("could not get document")
                    }
                };
                if headers.is_empty() {
                    let json = serde_json::to_string(&document.data)
                        .expect("could not serialise document");
                    cells.push(json);
                } else {
                    // This is really complicated, we could land in the same group but be from
                    // different hunts that have different headers, that also could even overlap...
                    // Because we group we won't be able to reliably handle clashes.
                    let mut hids = HashSet::new();
                    for (hid, _) in &ids {
                        hids.insert(hid);
                    }
                    let wrapper = match &document.kind {
                        FileKind::Evtx => crate::evtx::Wrapper(&document.data),
                        _ => continue,
                    };
                    let mut hdrs = HashMap::new();
                    for hid in hids {
                        let hunt = hunts.get(hid).expect("could not get hunt");
                        let fields = match &hunt.kind {
                            crate::hunt::HuntKind::Group { .. } => {
                                &groups.get(&hunt.id).expect("could not get group").fields
                            }
                            crate::hunt::HuntKind::Rule { .. } => {
                                &rules.get(&hunt.id).expect("could not get rule").fields
                            }
                        };
                        let flds: HashMap<_, _> =
                            fields.iter().map(|f| (&f.name, &f.from)).collect();
                        for header in &headers {
                            if let Some(from) = flds.get(header) {
                                let mapper = Mapper(&hunt.mapper, &wrapper);
                                if let Some(value) = mapper.find(&from).and_then(|v| v.to_string())
                                {
                                    hdrs.insert(header, value);
                                }
                            }
                        }
                    }
                    for header in &headers {
                        if let Some(value) = hdrs.get(header) {
                            cells.push(value.to_string());
                        } else {
                            cells.push("".to_owned());
                        }
                    }
                }
                csv.write_record(cells)?;
            }
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct Detection<'a> {
    pub group: &'a String,
    #[serde(flatten)]
    pub kind: &'a Kind,
    pub name: &'a String,
    pub timestamp: String,

    pub authors: &'a Vec<String>,
    pub level: &'a Level,
    pub source: &'a RuleKind,
    pub status: &'a Status,
}

pub fn print_json(
    detections: &[Detections],
    rules: &HashMap<RuleKind, Vec<(Uuid, Chainsaw)>>,
    local: bool,
    timezone: Option<Tz>,
) -> crate::Result<()> {
    let mut rs: HashMap<_, _> = HashMap::new();
    for (kind, rules) in rules {
        for (id, rule) in rules {
            rs.insert(id, (kind, rule));
        }
    }
    let mut detections = detections
        .iter()
        .map(|d| {
            let mut detections = Vec::with_capacity(d.hits.len());
            for hit in &d.hits {
                let (kind, rule) = rs.get(&hit.rule).expect("could not get rule!");
                let localised = if let Some(timezone) = timezone {
                    timezone
                        .from_local_datetime(&hit.timestamp)
                        .single()
                        .expect("failed to localise timestamp")
                        .to_rfc3339()
                } else if local {
                    Utc.from_local_datetime(&hit.timestamp)
                        .single()
                        .expect("failed to localise timestamp")
                        .to_rfc3339()
                } else {
                    DateTime::<Utc>::from_utc(hit.timestamp.clone(), Utc).to_rfc3339()
                };
                detections.push(Detection {
                    authors: &rule.authors,
                    group: &rule.group,
                    kind: &d.kind,
                    level: &rule.level,
                    name: &rule.name,
                    source: kind,
                    status: &rule.status,
                    timestamp: localised,
                })
            }
            detections
        })
        .flatten()
        .collect::<Vec<Detection>>();
    detections.sort_by(|x, y| x.timestamp.cmp(&y.timestamp));
    cs_print_json!(&detections)?;
    Ok(())
}
