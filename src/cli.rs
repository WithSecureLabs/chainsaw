use std::collections::HashMap;

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use chrono_tz::Tz;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use prettytable::{cell, format, Row, Table};
use tau_engine::Document;

use crate::hunt::{Detection, Detections, Kind, Mapping};
use crate::rule::Rule;

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

pub fn print_detections(
    detections: &[Detections],
    mappings: &[Mapping],
    rules: &[Rule],
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

    let mappings: HashMap<_, HashMap<_, _>> = mappings
        .iter()
        .map(|m| (&m.name, m.groups.iter().map(|g| (&g.name, g)).collect()))
        .collect();
    let rules: HashMap<_, _> = rules.iter().map(|r| (&r.tag, r)).collect();

    // Do a signle unfold...
    let mut grouped: HashMap<
        (&Option<String>, &String),
        Vec<(&NaiveDateTime, &Kind, Vec<&String>)>,
    > = HashMap::new();
    for detection in detections {
        let mut tags: HashMap<(&Option<String>, &String), (&NaiveDateTime, Vec<&String>)> =
            HashMap::new();
        for hit in &detection.hits {
            let tags = tags
                .entry((&hit.mapping, &hit.group))
                .or_insert((&hit.timestamp, vec![]));
            (*tags).1.push(&hit.tag);
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
        let (mapping, group) = key;
        if let Some(mapping) = mapping {
            if let Some(groups) = mappings.get(mapping) {
                let group = groups.get(&group).expect("could not get group!");
                let mut header = vec![
                    cell!("timestamp").style_spec("c"),
                    cell!("detections").style_spec("c"),
                ];
                if let Some(default) = group.default.as_ref() {
                    for field in default {
                        header.push(cell!(field).style_spec("c"));
                    }
                } else {
                    header.push(cell!("data").style_spec("c"));
                }
                table.add_row(Row::new(header));
                for (timestamp, kind, mut tags) in grouped {
                    tags.sort();
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
                        for tag in tags {
                            let rule = rules.get(&tag).expect("could not get rule");
                            table.add_row(Row::new(vec![
                                cell!(tag),
                                cell!(rule.authors.join("\n")),
                                cell!(rule.level),
                                cell!(rule.status),
                            ]));
                        }
                        cells.push(cell!(table));
                    } else {
                        cells.push(cell!(tags
                            .iter()
                            .map(|tag| format!("{} {}", RULE_PREFIX, tag.as_str()))
                            .collect::<Vec<_>>()
                            .join("\n")));
                    }
                    let document = match kind {
                        Kind::Individual { document } => document,
                        _ => continue,
                    };
                    if let Some(default) = group.default.as_ref() {
                        for field in default {
                            if let Some(value) = group
                                .fields
                                .get(field)
                                .and_then(|k| document.data.find(k))
                                .and_then(|v| v.to_string())
                            {
                                cells.push(cell!(format_field_length(&value, full, column_width)));
                            } else {
                                cells.push(cell!(""));
                            }
                        }
                    } else {
                        let json = serde_json::to_string(&document.data)
                            .expect("could not serialise document");
                        cells.push(cell!(format_field_length(&json, false, column_width)));
                    }
                    table.add_row(Row::new(cells));
                }
            }
        }
        cs_greenln!("\n[+] Group: {}", key.1);
        cs_print_table!(table);
    }
}

pub fn print_json(
    detections: &[Detections],
    rules: &[Rule],
    local: bool,
    timezone: Option<Tz>,
) -> crate::Result<()> {
    // TODO: Fixme...
    let ruleset = "sigma".to_owned();
    let rules: HashMap<_, _> = rules.iter().map(|r| (&r.tag, r)).collect();
    let mut detections = detections
        .iter()
        .map(|d| {
            let mut detections = Vec::with_capacity(d.hits.len());
            for hit in &d.hits {
                let rule = rules.get(&hit.tag).expect("could not get rule!");
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
                    group: &hit.group,
                    kind: &d.kind,
                    level: &rule.level,
                    name: &hit.tag,
                    source: &ruleset,
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
