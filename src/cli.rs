use std::collections::{hash_map::DefaultHasher, HashMap, HashSet};
use std::fs;

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use chrono_tz::Tz;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use prettytable::{cell, format, Row, Table};
use serde::Serialize;
use std::hash::{Hash, Hasher};
use tau_engine::Document;
use uuid::Uuid;

use crate::file::Kind as FileKind;
use crate::hunt::{Detections, Hunt, Kind};
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
        .replace('\n', "")
        .replace('\r', "")
        .replace('\t', "")
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

pub struct Grouping<'a> {
    hits: Vec<Hit<'a>>,
    kind: &'a Kind,
    timestamp: &'a NaiveDateTime,
}

pub struct Hit<'a> {
    hunt: &'a Hunt,
    rule: &'a Chainsaw,
}

pub fn print_detections(
    detections: &[Detections],
    hunts: &[Hunt],
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
    let mut headers: HashMap<&String, (Vec<String>, HashSet<String>)> = HashMap::new();
    for hunt in hunts {
        let headers = headers
            .entry(&hunt.group)
            .or_insert((vec![], HashSet::new()));
        // NOTE: We only support count in aggs atm so we can inject that value in...!
        // NOTE: This will not work for sigma based aggs...
        if hunt.is_aggregation() {
            (*headers).0.push("count".to_owned());
            (*headers).1.insert("count".to_owned());
        }
        for field in hunt.mapper.fields() {
            if field.visible && !headers.1.contains(&field.name) {
                (*headers).0.push(field.name.clone());
                (*headers).1.insert(field.name.clone());
            }
        }
    }
    let mut headers: HashMap<_, _> = headers.into_iter().map(|(k, (v, _))| (k, v)).collect();

    // Build lookups
    let hunts: HashMap<_, _> = hunts.iter().map(|h| (&h.id, h)).collect();
    let rules: HashMap<_, _> = rules.values().flatten().map(|r| (&r.0, &r.1)).collect();

    // Unpack detections
    let mut groups: HashMap<&String, Vec<Grouping>> = HashMap::new();
    for detection in detections {
        let mut hits: HashMap<(&String, &NaiveDateTime), Vec<Hit>> = HashMap::new();
        for hit in &detection.hits {
            let hunt = &hunts.get(&hit.hunt).expect("could not get hunt");
            let rule = &rules.get(&hit.rule).expect("could not get rule");
            let hits = hits.entry((&hunt.group, &hit.timestamp)).or_insert(vec![]);
            (*hits).push(Hit { hunt, rule });
        }
        for ((group, timestamp), mut hits) in hits {
            hits.sort_by(|x, y| x.rule.name.cmp(&y.rule.name));
            let groups = groups.entry(group).or_insert(vec![]);
            (*groups).push(Grouping {
                kind: &detection.kind,
                timestamp,
                hits,
            });
        }
    }

    let mut keys = groups.keys().cloned().collect::<Vec<_>>();
    keys.sort();
    for key in keys {
        let mut group = groups.remove(&key).expect("could not get grouping!");
        group.sort_by(|x, y| x.timestamp.cmp(y.timestamp));

        let mut table = Table::new();
        table.set_format(format);

        if let Some(headers) = headers.remove(key) {
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

            for grouping in group {
                let localised = if let Some(timezone) = timezone {
                    timezone
                        .from_local_datetime(grouping.timestamp)
                        .single()
                        .expect("failed to localise timestamp")
                        .to_rfc3339()
                } else if local {
                    Utc.from_local_datetime(grouping.timestamp)
                        .single()
                        .expect("failed to localise timestamp")
                        .to_rfc3339()
                } else {
                    DateTime::<Utc>::from_utc(*grouping.timestamp, Utc).to_rfc3339()
                };

                // NOTE: Currently we don't do any fancy outputting for aggregates so we can cut some
                // corners here!
                let count;
                let document = match grouping.kind {
                    Kind::Individual { document } => {
                        count = 1;
                        document
                    }
                    Kind::Aggregate { documents } => {
                        count = documents.len();
                        documents.first().expect("could not get document")
                    }
                };

                let mut rows = vec![];
                let mut seen: HashMap<u64, Vec<&Chainsaw>> = HashMap::new();
                if headers.is_empty() {
                    let json = serde_json::to_string(&document.data)
                        .expect("could not serialise document");
                    let rules = grouping.hits.iter().map(|hit| hit.rule).collect();
                    rows.push((
                        0,
                        vec![cell!(format_field_length(&json, false, column_width))],
                    ));
                    seen.insert(0, rules);
                } else {
                    // What we do here is hash each row since if the fields are the same but the values
                    // are not then we would lose data, so in this case we split the row
                    for hit in &grouping.hits {
                        let wrapper;
                        let mapped = match &document.kind {
                            FileKind::Evtx => {
                                wrapper = crate::evtx::Wrapper(&document.data);
                                hit.hunt.mapper.mapped(&wrapper)
                            }
                            FileKind::Json | FileKind::Xml => {
                                hit.hunt.mapper.mapped(&document.data)
                            }
                            FileKind::Unknown => continue,
                        };
                        let fields: HashMap<_, _> = hit
                            .hunt
                            .mapper
                            .fields()
                            .iter()
                            .map(|f| (&f.name, f))
                            .collect();
                        let mut cells = vec![];
                        let mut hasher = DefaultHasher::new();
                        for header in &headers {
                            if let Some(field) = fields.get(header) {
                                if let Some(value) = mapped.find(&field.from) {
                                    match value.to_string() {
                                        Some(v) => {
                                            v.hash(&mut hasher);
                                            cells.push(cell!(format_field_length(
                                                &v,
                                                full,
                                                column_width
                                            )));
                                        }
                                        None => {
                                            "<see raw event>".hash(&mut hasher);
                                            cells.push(cell!("<see raw event>"));
                                        }
                                    }
                                    continue;
                                }
                            } else if header == "count" {
                                cells.push(cell!(count));
                                continue;
                            }
                            cells.push(cell!(""));
                        }
                        let id = hasher.finish();
                        if !seen.contains_key(&id) {
                            rows.push((id, cells));
                        }
                        let rules = seen.entry(id).or_insert(vec![]);
                        (*rules).push(hit.rule);
                    }
                }

                for (id, row) in rows {
                    let rules = seen.remove(&id).expect("could not get rules");
                    let mut cells = vec![cell!(localised)];
                    if metadata {
                        let mut table = Table::new();
                        table.add_row(Row::new(vec![
                            cell!("name").style_spec("c"),
                            cell!("authors").style_spec("c"),
                            cell!("level").style_spec("c"),
                            cell!("status").style_spec("c"),
                        ]));
                        for rule in &rules {
                            table.add_row(Row::new(vec![
                                cell!(rule.name),
                                cell!(rule.authors.join("\n")),
                                cell!(rule.level),
                                cell!(rule.status),
                            ]));
                        }
                        cells.push(cell!(table));
                    } else {
                        cells.push(cell!(rules
                            .iter()
                            .map(|rule| format!("{} {}", RULE_PREFIX, rule.name))
                            .collect::<Vec<_>>()
                            .join("\n")));
                    }
                    cells.extend(row);
                    table.add_row(Row::new(cells));
                }
            }
        }

        cs_greenln!("\n[+] Group: {}", key);
        cs_print_table!(table);
    }
}

pub fn print_csv(
    detections: &[Detections],
    hunts: &[Hunt],
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
    let mut headers: HashMap<&String, (Vec<String>, HashSet<String>)> = HashMap::new();
    for hunt in hunts {
        let headers = headers
            .entry(&hunt.group)
            .or_insert((vec![], HashSet::new()));
        // NOTE: We only support count in aggs atm so we can inject that value in...!
        if hunt.is_aggregation() {
            (*headers).0.push("count".to_owned());
            (*headers).1.insert("count".to_owned());
        }
        for field in hunt.mapper.fields() {
            if field.visible && !headers.1.contains(&field.name) {
                (*headers).0.push(field.name.clone());
                (*headers).1.insert(field.name.clone());
            }
        }
    }
    let mut headers: HashMap<_, _> = headers.into_iter().map(|(k, (v, _))| (k, v)).collect();

    // Build lookups
    let hunts: HashMap<_, _> = hunts.iter().map(|h| (&h.id, h)).collect();
    let rules: HashMap<_, _> = rules.values().flatten().map(|r| (&r.0, &r.1)).collect();

    // Unpack detections
    let mut groups: HashMap<&String, Vec<Grouping>> = HashMap::new();
    for detection in detections {
        let mut hits: HashMap<(&String, &NaiveDateTime), Vec<Hit>> = HashMap::new();
        for hit in &detection.hits {
            let hunt = &hunts.get(&hit.hunt).expect("could not get hunt");
            let rule = &rules.get(&hit.rule).expect("could not get rule");
            let hits = hits.entry((&hunt.group, &hit.timestamp)).or_insert(vec![]);
            (*hits).push(Hit { hunt, rule });
        }
        for ((group, timestamp), mut hits) in hits {
            hits.sort_by(|x, y| x.rule.name.cmp(&y.rule.name));
            let groups = groups.entry(group).or_insert(vec![]);
            (*groups).push(Grouping {
                kind: &detection.kind,
                timestamp,
                hits,
            });
        }
    }

    let mut keys = groups.keys().cloned().collect::<Vec<_>>();
    keys.sort();
    for key in keys {
        let mut group = groups.remove(&key).expect("could not get grouping!");
        group.sort_by(|x, y| x.timestamp.cmp(y.timestamp));

        // FIXME: Handle name clashes
        let filename = format!("{}.csv", key.replace(' ', "_").to_lowercase());
        let path = directory.join(&filename);
        let mut csv = prettytable::csv::Writer::from_path(path)?;
        cs_eprintln!("[+] Created {}", filename);

        if let Some(headers) = headers.remove(key) {
            let mut cells = vec!["timestamp", "detections"];
            if headers.is_empty() {
                cells.push("data");
            } else {
                for header in &headers {
                    cells.push(header);
                }
            }
            csv.write_record(cells)?;

            for grouping in group {
                let localised = if let Some(timezone) = timezone {
                    timezone
                        .from_local_datetime(grouping.timestamp)
                        .single()
                        .expect("failed to localise timestamp")
                        .to_rfc3339()
                } else if local {
                    Utc.from_local_datetime(grouping.timestamp)
                        .single()
                        .expect("failed to localise timestamp")
                        .to_rfc3339()
                } else {
                    DateTime::<Utc>::from_utc(*grouping.timestamp, Utc).to_rfc3339()
                };

                // NOTE: Currently we don't do any fancy outputting for aggregates so we can cut some
                // corners here!
                let count;
                let document = match grouping.kind {
                    Kind::Individual { document } => {
                        count = 1;
                        document
                    }
                    Kind::Aggregate { documents } => {
                        count = documents.len();
                        documents.first().expect("could not get document")
                    }
                };

                let mut rows = vec![];
                let mut seen: HashMap<u64, Vec<&Chainsaw>> = HashMap::new();
                if headers.is_empty() {
                    let json = serde_json::to_string(&document.data)
                        .expect("could not serialise document");
                    let rules = grouping.hits.iter().map(|hit| hit.rule).collect();
                    rows.push((0, vec![json]));
                    seen.insert(0, rules);
                } else {
                    // What we do here is hash each row since if the fields are the same but the values
                    // are not then we would lose data, so in this case we split the row
                    for hit in &grouping.hits {
                        let wrapper;
                        let mapped = match &document.kind {
                            FileKind::Evtx => {
                                wrapper = crate::evtx::Wrapper(&document.data);
                                hit.hunt.mapper.mapped(&wrapper)
                            }
                            FileKind::Json | FileKind::Xml => {
                                hit.hunt.mapper.mapped(&document.data)
                            }
                            FileKind::Unknown => continue,
                        };

                        let fields: HashMap<_, _> = hit
                            .hunt
                            .mapper
                            .fields()
                            .iter()
                            .map(|f| (&f.name, f))
                            .collect();
                        let mut cells = vec![];
                        let mut hasher = DefaultHasher::new();
                        for header in &headers {
                            if let Some(field) = fields.get(header) {
                                if let Some(value) = mapped.find(&field.from) {
                                    match value.to_string() {
                                        Some(v) => {
                                            v.hash(&mut hasher);
                                            cells.push(v);
                                        }
                                        None => {
                                            "<see raw event>".hash(&mut hasher);
                                            cells.push("<see raw event>".to_owned());
                                        }
                                    }
                                    continue;
                                }
                            } else if header == "count" {
                                cells.push(count.to_string());
                                continue;
                            }
                            cells.push("".to_owned());
                        }
                        let id = hasher.finish();
                        if !seen.contains_key(&id) {
                            rows.push((id, cells));
                        }
                        let rules = seen.entry(id).or_insert(vec![]);
                        (*rules).push(hit.rule);
                    }
                }

                for (id, row) in rows {
                    let rules = seen.remove(&id).expect("could not get rules");
                    let mut cells = vec![localised.clone()];
                    cells.push(
                        rules
                            .iter()
                            .map(|rule| rule.name.to_string())
                            .collect::<Vec<_>>()
                            .join(";"),
                    );
                    cells.extend(row);
                    csv.write_record(cells)?;
                }
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
        .flat_map(|d| {
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
                    DateTime::<Utc>::from_utc(hit.timestamp, Utc).to_rfc3339()
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
        .collect::<Vec<Detection>>();
    detections.sort_by(|x, y| x.timestamp.cmp(&y.timestamp));
    cs_print_json!(&detections)?;
    Ok(())
}
