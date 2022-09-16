use std::collections::{hash_map::DefaultHasher, BTreeMap, HashMap, HashSet};
use std::fs;

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use chrono_tz::Tz;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use prettytable::{cell, format, Row, Table};
use serde::Serialize;
use serde_json::{Map, Number, Value as Json};
use std::hash::{Hash, Hasher};
use tau_engine::{Document, Value as Tau};
use uuid::Uuid;

use crate::file::Kind as FileKind;
use crate::hunt::{Detections, Hunt, Kind};
use crate::rule::{Kind as RuleKind, Level, Rule, Status};
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

pub fn format_field_length(data: &str, full_output: bool, col_width: u32) -> String {
    // Take the context_field and format it for printing. Remove newlines, break into even chunks etc.
    // If this is a scheduled task we need to parse the XML to make it more readable
    let mut scratch = data
        .replace('\n', "")
        .replace('\r', "")
        .replace('\t', "")
        .replace("  ", " ")
        .chars()
        .collect::<Vec<char>>()
        .chunks(col_width as usize)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<String>>()
        .join("\n");

    let truncate_len = 500;

    if !full_output && scratch.len() > truncate_len {
        scratch.truncate(truncate_len);
        scratch.push_str("...\n(use --full to show all content)");
    }

    scratch
}

fn split_tag(tag_name: &str) -> String {
    let mut count = 0;
    let mut chars = Vec::with_capacity(tag_name.len());
    for char in tag_name.chars() {
        count += 1;
        if count > 20 && char.is_whitespace() {
            count = 0;
            chars.push('\n');
        } else {
            chars.push(char);
        }
    }
    chars.into_iter().collect()
}

fn format_time(event_time: String) -> String {
    let chunks = event_time.rsplit('.').last();
    match chunks {
        Some(e) => e.replace('T', " ").replace('"', ""),
        None => event_time,
    }
}

pub struct Grouping<'a> {
    hits: Vec<Hit<'a>>,
    kind: &'a Kind,
    timestamp: &'a NaiveDateTime,
}

pub struct Hit<'a> {
    hunt: &'a Hunt,
    rule: &'a Rule,
}

pub fn print_log(
    detections: &[Detections],
    hunts: &[Hunt],
    rules: &BTreeMap<Uuid, Rule>,
    local: bool,
    timezone: Option<Tz>,
) -> crate::Result<()> {
    let hunts: HashMap<_, _> = hunts.iter().map(|h| (&h.id, h)).collect();
    let mut rule_width = 1;
    for rule in rules.values() {
        let width = rule.name().len();
        if width > rule_width {
            rule_width = width;
        }
    }

    let mut rows = vec![];
    for detection in detections {
        for hit in &detection.hits {
            rows.push((hit, &detection.kind));
        }
    }
    rows.sort_by(|x, y| x.0.timestamp.cmp(&y.0.timestamp));
    for (hit, kind) in rows {
        let hunt = &hunts.get(&hit.hunt).expect("could not get hunt");
        let rule = &rules.get(&hit.rule).expect("could not get rule");
        let mut columns = vec![];

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
        columns.push(localised.to_string());

        let count;
        let document = match kind {
            Kind::Individual { document } => {
                count = 1;
                document
            }
            Kind::Aggregate { documents } => {
                count = documents.len();
                documents.first().expect("could not get document")
            }
        };

        let name = match rule {
            Rule::Chainsaw(rule) => {
                columns.push("c".to_string());
                &rule.name
            }
            Rule::Sigma(rule) => {
                columns.push("σ".to_string());
                &rule.name
            }
        };
        //columns.push(format!("{: <width$}", name, width = rule_width - 1));
        //columns.push(format!("{: >6}", count));
        columns.push(name.to_string());
        columns.push(format!("{}", count));

        let mut values = vec![];
        for field in hunt.mapper.fields() {
            if field.visible {
                let wrapper;
                let mapped = match &document.kind {
                    FileKind::Evtx => {
                        wrapper = crate::evtx::Wrapper(&document.data);
                        hunt.mapper.mapped(&wrapper)
                    }
                    FileKind::Json | FileKind::Jsonl | FileKind::Mft | FileKind::Xml => {
                        hunt.mapper.mapped(&document.data)
                    }
                    FileKind::Unknown => continue,
                };
                let fields: HashMap<_, _> =
                    hunt.mapper.fields().iter().map(|f| (&f.name, f)).collect();
                if let Some(field) = fields.get(&field.name) {
                    if let Some(value) = mapped.find(&field.from) {
                        match value.to_string() {
                            Some(v) => {
                                values.push(v);
                            }
                            None => {
                                values.push("<see raw event>".to_string());
                            }
                        }
                    }
                }
            }
        }
        columns.push(values.join("  ::  "));

        println!("{}", columns.join("  |  "));
    }
    Ok(())
}

pub fn print_detections(
    detections: &[Detections],
    hunts: &[Hunt],
    rules: &BTreeMap<Uuid, Rule>,
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
            hits.sort_by(|x, y| x.rule.name().cmp(y.rule.name()));
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
                let mut localised = if let Some(timezone) = timezone {
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

                localised = format_time(localised);

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
                let mut seen: HashMap<u64, Vec<&Rule>> = HashMap::new();
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
                            FileKind::Json | FileKind::Jsonl | FileKind::Mft | FileKind::Xml => {
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
                                                column_width,
                                            )));
                                        }
                                        None => {
                                            let mut yaml =
                                                serde_yaml::to_string(&tau_to_json(value))
                                                    .expect("could not get yaml");

                                            yaml = yaml
                                                .split('\n')
                                                .collect::<Vec<&str>>()
                                                .iter()
                                                .map(|x| format_field_length(x, full, column_width))
                                                .collect::<Vec<String>>()
                                                .join("\n")
                                                .replace("\\n", "\n");
                                            yaml.hash(&mut hasher);
                                            cells.push(cell!(yaml));
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
                            cell!("").style_spec("c"),
                            cell!("name").style_spec("c"),
                            cell!("authors").style_spec("c"),
                            cell!("level").style_spec("c"),
                            cell!("status").style_spec("c"),
                        ]));
                        for rule in &rules {
                            match rule {
                                Rule::Chainsaw(c) => {
                                    table.add_row(Row::new(vec![
                                        cell!('c'),
                                        cell!(split_tag(&c.name)),
                                        cell!(c.authors.join("\n")),
                                        cell!(c.level),
                                        cell!(c.status),
                                    ]));
                                }
                                Rule::Sigma(s) => {
                                    table.add_row(Row::new(vec![
                                        cell!('σ'),
                                        cell!(split_tag(&s.name)),
                                        cell!(s.authors.join("\n")),
                                        cell!(s.level),
                                        cell!(s.status),
                                    ]));
                                }
                            }
                        }
                        cells.push(cell!(table));
                    } else {
                        cells.push(cell!(rules
                            .iter()
                            .map(|rule| format!("{} {}", RULE_PREFIX, split_tag(rule.name())))
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
    rules: &BTreeMap<Uuid, Rule>,
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
            hits.sort_by(|x, y| x.rule.name().cmp(y.rule.name()));
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
                let mut seen: HashMap<u64, Vec<&Rule>> = HashMap::new();
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
                            FileKind::Json | FileKind::Jsonl | FileKind::Mft | FileKind::Xml => {
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
                                            let yaml = serde_yaml::to_string(&tau_to_json(value))
                                                .expect("could not get yaml");
                                            yaml.hash(&mut hasher);
                                            cells.push(yaml);
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
                            .map(|rule| rule.name().to_string())
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
    pub source: RuleKind,
    pub status: &'a Status,

    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub sigma: Option<Sigma<'a>>,
}

#[derive(Debug, Serialize)]
pub struct Sigma<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub falsepositives: &'a Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logsource: &'a Option<crate::rule::sigma::LogSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub references: &'a Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: &'a Option<Vec<String>>,
}

pub fn print_json(
    detections: &[Detections],
    hunts: &[Hunt],
    rules: &BTreeMap<Uuid, Rule>,
    local: bool,
    timezone: Option<Tz>,
) -> crate::Result<()> {
    let hunts: HashMap<_, _> = hunts.iter().map(|h| (&h.id, h)).collect();
    let mut detections = detections
        .iter()
        .flat_map(|d| {
            let mut detections = Vec::with_capacity(d.hits.len());
            for hit in &d.hits {
                let hunt = hunts.get(&hit.hunt).expect("could not get rule!");
                let rule = rules.get(&hit.rule).expect("could not get rule!");
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
                match rule {
                    Rule::Chainsaw(c) => detections.push(Detection {
                        authors: &c.authors,
                        group: &hunt.group,
                        kind: &d.kind,
                        level: &c.level,
                        name: &c.name,
                        source: RuleKind::Chainsaw,
                        status: &c.status,
                        timestamp: localised,

                        sigma: None,
                    }),
                    Rule::Sigma(s) => {
                        let sigma = Sigma {
                            falsepositives: &s.falsepositives,
                            id: &s.id,
                            logsource: &s.logsource,
                            references: &s.references,
                            tags: &s.tags,
                        };
                        detections.push(Detection {
                            authors: &s.authors,
                            group: &hunt.group,
                            kind: &d.kind,
                            level: &s.level,
                            name: &s.name,
                            source: RuleKind::Sigma,
                            status: &s.status,
                            timestamp: localised,

                            sigma: Some(sigma),
                        })
                    }
                }
            }
            detections
        })
        .collect::<Vec<Detection>>();
    detections.sort_by(|x, y| x.timestamp.cmp(&y.timestamp));
    cs_print_json!(&detections)?;
    Ok(())
}

pub fn tau_to_json(tau: Tau) -> Json {
    match tau {
        Tau::Null => Json::Null,
        Tau::Bool(b) => Json::Bool(b),
        Tau::Float(f) => Json::Number(Number::from_f64(f).expect("could not set f64")),
        Tau::Int(i) => Json::Number(Number::from(i)),
        Tau::UInt(u) => Json::Number(Number::from(u)),
        Tau::String(s) => Json::String(s.to_string()),
        Tau::Array(a) => Json::Array(a.iter().map(tau_to_json).collect()),
        Tau::Object(o) => {
            let mut map = Map::new();
            for k in o.keys() {
                let v = o.get(&k).expect("could not get value");
                map.insert(k.to_string(), tau_to_json(v));
            }
            Json::Object(map)
        }
    }
}
