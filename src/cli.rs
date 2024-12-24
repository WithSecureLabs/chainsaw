use std::collections::{hash_map::DefaultHasher, BTreeMap, HashMap, HashSet};
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::*;
use std::time::Duration;

use chrono::{DateTime, Local, NaiveDateTime, SecondsFormat, TimeZone, Utc};
use chrono_tz::Tz;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use prettytable::{cell, format, Row, Table};
use rustc_hash::FxHashMap;
use serde::Serialize;
use serde_json::{value::RawValue, Map, Number, Value as Json};
use tau_engine::{Document, Value as Tau};
use uuid::Uuid;

use crate::analyse::shimcache::{TimelineEntity, TimelineTimestamp, TimestampType};
use crate::file::hve::shimcache::EntryType;
use crate::file::Kind as FileKind;
use crate::hunt::{Detections, Hunt, Kind};
use crate::rule::{Kind as RuleKind, Level, Rule, Status};
use crate::value::Value;
use crate::write::writer;

#[cfg(not(windows))]
pub const RULE_PREFIX: &str = "‣";

#[cfg(windows)]
pub const RULE_PREFIX: &str = "+";

#[cfg(not(windows))]
const TICK_SETTINGS: (&str, u64) = ("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏ ", 80);

#[cfg(windows)]
const TICK_SETTINGS: (&str, u64) = (r"-\|/-", 200);

pub fn init_progress_bar(
    size: u64,
    msg: String,
    verbose: bool,
    prefix: String,
) -> indicatif::ProgressBar {
    let pb = ProgressBar::new(size);
    if verbose {
        pb.set_draw_target(ProgressDrawTarget::hidden());
    } else {
        unsafe {
            match crate::write::WRITER.quiet {
                true => pb.set_draw_target(ProgressDrawTarget::hidden()),
                false => pb.set_draw_target(ProgressDrawTarget::stderr()),
            }
        }
    }
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                format!(
                    "{{msg}}[+] {} [{{bar:40}}] {{pos}}/{{len}} {{spinner}} [{{elapsed_precise}}]",
                    prefix
                )
                .as_str(),
            )
            .expect("could not set template")
            .tick_chars(TICK_SETTINGS.0)
            .progress_chars("=>-"),
    );

    pb.set_message(msg);
    pb.enable_steady_tick(Duration::from_millis(TICK_SETTINGS.1));
    pb
}

pub fn format_field_length(data: &str, full_output: bool, col_width: u32) -> String {
    // Take the context_field and format it for printing. Remove newlines, break into even chunks etc.
    // If this is a scheduled task we need to parse the XML to make it more readable
    let mut scratch = data
        .replace(['\n', '\r', '\t'], "")
        .replace("  ", " ")
        .chars()
        .collect::<Vec<char>>()
        .chunks(col_width as usize)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<String>>()
        .join("\n");

    let truncate_len = 496;

    if !full_output && scratch.len() > truncate_len {
        scratch = match scratch.char_indices().nth(truncate_len) {
            None => scratch,
            Some((i, _)) => scratch[..i].to_owned(),
        };
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
    kind: &'a Kind<'a>,
    timestamp: &'a NaiveDateTime,
}

pub struct Hit<'a> {
    hunt: &'a Hunt,
    rule: &'a Rule,
}

// HACK: Don't do this at home... its mega slow, but due to prior abstractions and optimisations, this
// is the only way to consolidate aggregates for now
fn agg_to_doc<'a>(
    hunts: &[&Hunt],
    documents: &[crate::hunt::Document<'a>],
) -> crate::Result<crate::hunt::Document<'a>> {
    let mut scratch: HashMap<String, HashSet<String>> = HashMap::default();
    for hunt in hunts {
        let fields = hunt.mapper.fields();
        for document in documents {
            let data: Value;
            let wrapper;
            let mapped = match &document.kind {
                FileKind::Evtx => {
                    data = bincode::deserialize::<Value>(&document.data)?;
                    wrapper = crate::evtx::Wrapper(&data);
                    hunt.mapper.mapped(&wrapper)
                }
                FileKind::Hve
                | FileKind::Json
                | FileKind::Jsonl
                | FileKind::Mft
                | FileKind::Xml
                | FileKind::Esedb => {
                    data = bincode::deserialize::<Value>(&document.data)?;
                    hunt.mapper.mapped(&data)
                }
                FileKind::Unknown => continue,
            };
            for field in fields {
                if field.visible {
                    if let Some(value) = mapped.find(&field.from) {
                        let entry = scratch
                            .entry(field.from.clone())
                            .or_insert(HashSet::with_capacity(documents.len()));
                        match value.to_string() {
                            Some(v) => {
                                entry.insert(v);
                            }
                            None => {
                                entry.insert("<see raw event>".to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    let first = documents.first().expect("missing document");
    let mut doc: FxHashMap<String, Value> = FxHashMap::default();
    let mut keys = scratch.keys().collect::<Vec<_>>();
    keys.sort();
    for k in keys {
        let v = scratch.get(k).expect("could not get value");
        let mut v = v.iter().cloned().collect::<Vec<_>>();
        v.sort();
        // NOTE: Lazy way of re-nesting object...
        let mut parts = k.split('.').peekable();
        let mut entry = doc
            .entry(parts.next().expect("missing key").to_owned())
            .or_insert(Value::Object(FxHashMap::default()));
        while let Some(part) = parts.next() {
            if let Value::Object(o) = entry {
                if parts.peek().is_none() {
                    if part.ends_with(']') && part.contains('[') {
                        let mut ki = part.split('[');
                        let k = ki.next().expect("missing key");
                        let i: usize = match ki
                            .next()
                            .and_then(|i| i.strip_suffix(']'))
                            .and_then(|i| i.parse::<usize>().ok())
                        {
                            Some(i) => i,
                            None => break,
                        };
                        if let Value::Array(vec) =
                            o.entry(k.to_owned()).or_insert(Value::Array(vec![]))
                        {
                            for _ in 0..(i - vec.len()) {
                                vec.push(Value::Null);
                            }
                            vec.push(Value::String(v.join(", ")));
                        }
                    } else {
                        o.insert(part.to_owned(), Value::String(v.join(", ")));
                    }
                    break;
                } else {
                    entry = o
                        .entry(part.to_owned())
                        .or_insert(Value::Object(FxHashMap::default()));
                }
            } else {
                break;
            }
        }
    }
    Ok(crate::hunt::Document {
        kind: first.kind.clone(),
        path: first.path,
        data: bincode::serialize(&Value::Object(doc))
            .expect("could not serialise collated documents"),
    })
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
            timezone.from_utc_datetime(&hit.timestamp).to_rfc3339()
        } else if local {
            Local.from_utc_datetime(&hit.timestamp).to_rfc3339()
        } else {
            Utc.from_utc_datetime(&hit.timestamp).to_rfc3339()
        };
        columns.push(localised.to_string());

        let agg;
        let count;
        let document = match kind {
            Kind::Individual { document } => {
                count = 1;
                document
            }
            Kind::Aggregate { documents } => {
                count = documents.len();
                agg = agg_to_doc(&[hunt], documents)?;
                &agg
            }
            _ => unimplemented!(),
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
        columns.push(name.to_string());
        columns.push(format!("{}", count));

        let mut values = vec![];
        let data: Value;
        let wrapper;
        let mapped = match &document.kind {
            FileKind::Evtx => {
                data = bincode::deserialize::<Value>(&document.data)?;
                wrapper = crate::evtx::Wrapper(&data);
                hunt.mapper.mapped(&wrapper)
            }
            FileKind::Hve
            | FileKind::Json
            | FileKind::Jsonl
            | FileKind::Mft
            | FileKind::Xml
            | FileKind::Esedb => {
                data = bincode::deserialize::<Value>(&document.data)?;
                hunt.mapper.mapped(&data)
            }
            FileKind::Unknown => continue,
        };
        for field in hunt.mapper.fields() {
            if field.visible {
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
        columns.push(values.join("  ::  "));

        println!("{}", columns.join("  |  "));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
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
            headers.0.push("count".to_owned());
            headers.1.insert("count".to_owned());
        }
        for field in hunt.mapper.fields() {
            if field.visible && !headers.1.contains(&field.name) {
                headers.0.push(field.name.clone());
                headers.1.insert(field.name.clone());
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
            let hits = hits.entry((&hunt.group, &hit.timestamp)).or_default();
            (*hits).push(Hit { hunt, rule });
        }
        for ((group, timestamp), mut hits) in hits {
            hits.sort_by(|x, y| x.rule.name().cmp(y.rule.name()));
            let groups = groups.entry(group).or_default();
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
                    timezone.from_utc_datetime(grouping.timestamp).to_rfc3339()
                } else if local {
                    Local.from_utc_datetime(grouping.timestamp).to_rfc3339()
                } else {
                    Utc.from_utc_datetime(grouping.timestamp).to_rfc3339()
                };

                localised = format_time(localised);

                let agg;
                let count;
                let document = match grouping.kind {
                    Kind::Individual { document } => {
                        count = 1;
                        document
                    }
                    Kind::Aggregate { documents } => {
                        count = documents.len();
                        let hunts = grouping.hits.iter().map(|h| h.hunt).collect::<Vec<_>>();
                        agg = agg_to_doc(&hunts, documents).expect("could not collate aggregates");
                        &agg
                    }
                    _ => unimplemented!(),
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
                        let data: Value;
                        let wrapper;
                        let mapped = match &document.kind {
                            FileKind::Evtx => {
                                data = bincode::deserialize::<Value>(&document.data)
                                    .expect("could not decompress");
                                wrapper = crate::evtx::Wrapper(&data);
                                hit.hunt.mapper.mapped(&wrapper)
                            }
                            FileKind::Hve
                            | FileKind::Esedb
                            | FileKind::Json
                            | FileKind::Jsonl
                            | FileKind::Mft
                            | FileKind::Xml => {
                                data = bincode::deserialize::<Value>(&document.data)
                                    .expect("could not decompress");
                                hit.hunt.mapper.mapped(&data)
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
                                                .join("\n");
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
                        let rules = seen.entry(id).or_default();
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

pub fn print_shimcache_analysis_csv(timeline: &Vec<TimelineEntity>) -> crate::Result<()> {
    let path = &writer().path;
    let csv = if let Some(path) = path {
        Some(prettytable::csv::Writer::from_path(path)?)
    } else {
        None
    };
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

    fn format_ts(ts: &DateTime<Utc>) -> String {
        ts.to_rfc3339_opts(SecondsFormat::AutoSi, true)
    }

    let mut table = Table::new();
    table.set_format(format);
    let headers = [
        "Timestamp",
        "File Path",
        "Program Name",
        "SHA-1 Hash",
        "Timeline Entry Number",
        "Entry Type",
        "Timestamp Description",
        "Raw Entry",
    ];
    let header_cells = headers.map(|s| cell!(s)).to_vec();
    table.add_row(Row::new(header_cells));

    let mut timeline_entry_nr = 0;
    for entity in timeline {
        let mut timestamp = String::new();
        let mut file_path = String::new();
        let mut program_name = String::new();
        let mut entry_type = "";
        let mut ts_description = "";
        let mut raw_entry = String::new();

        if let Some(TimelineTimestamp::Exact(ts, _type)) = &entity.timestamp {
            timestamp = format_ts(ts);
        }
        if let Some(TimelineTimestamp::Exact(_ts, ts_type)) = &entity.timestamp {
            ts_description = match ts_type {
                TimestampType::AmcacheRangeMatch => "Amcache timestamp range match",
                TimestampType::NearTSMatch => "Timestamp near pair",
                TimestampType::PatternMatch => "Shimcache pattern match",
                TimestampType::ShimcacheLastUpdate => "Latest shimcache update",
            }
        };
        if let Some(shimcache_entry) = &entity.shimcache_entry {
            match &shimcache_entry.entry_type {
                EntryType::File { path } => {
                    entry_type = "ShimcacheFileEntry";
                    file_path = path.clone();
                }
                EntryType::Program {
                    program_name: name, ..
                } => {
                    entry_type = "ShimcacheProgramEntry";
                    program_name = name.clone();
                }
            };
        }

        if let Some(shimcache_entry) = &entity.shimcache_entry {
            raw_entry = serde_json::to_string(&shimcache_entry)?;
        }

        let timeline_entry_nr_string = timeline_entry_nr.to_string();
        let shimcache_row = [
            &timestamp,
            &file_path,
            &program_name,
            "",
            &timeline_entry_nr_string,
            entry_type,
            ts_description,
            &raw_entry,
        ];
        let cells = shimcache_row.map(|s| cell!(s)).to_vec();
        table.add_row(Row::new(cells));
        timeline_entry_nr += 1;

        // If there is an amcache time range or near ts match, add a separate row for it
        if let Some(TimelineTimestamp::Exact(
            _ts,
            TimestampType::AmcacheRangeMatch | TimestampType::NearTSMatch,
        )) = &entity.timestamp
        {
            if let Some(file_entry) = &entity.amcache_file {
                let amcache_timestamp = format_ts(&file_entry.key_last_modified_ts);
                let file_path = file_entry.path.clone();
                let sha1_hash = file_entry
                    .sha1_hash
                    .as_ref()
                    .unwrap_or(&String::new())
                    .to_string();
                let entry_type = "AmcacheFileEntry";
                let raw_entry = serde_json::to_string(file_entry.as_ref())?;
                let timeline_entry_nr_string = timeline_entry_nr.to_string();
                let amcache_row = [
                    &amcache_timestamp,
                    &file_path,
                    "",
                    &sha1_hash,
                    &timeline_entry_nr_string,
                    entry_type,
                    "",
                    &raw_entry,
                ];
                let cells = amcache_row.map(|s| cell!(s)).to_vec();
                table.add_row(Row::new(cells));
                timeline_entry_nr += 1;
            }
        }
    }
    if let Some(writer) = csv {
        table.to_csv_writer(writer)?;
    } else {
        // Truncate the number of columns for terminal output
        const N_FIRST_COLUMNS: usize = 4;
        for row in &mut table {
            for i in (N_FIRST_COLUMNS..row.len()).rev() {
                row.remove_cell(i);
            }
        }
        cs_print_table!(table);
        cs_eyellowln!("[!] Truncated output. Use --output to get all columns.");
    }

    Ok(())
}

pub fn print_csv(
    detections: &[Detections],
    hunts: &[Hunt],
    rules: &BTreeMap<Uuid, Rule>,
    local: bool,
    timezone: Option<Tz>,
) -> crate::Result<()> {
    let directory = writer()
        .path
        .as_ref()
        .expect("could not get output directory");
    fs::create_dir_all(directory)?;

    // Build headers
    let mut headers: HashMap<&String, (Vec<String>, HashSet<String>)> = HashMap::new();
    for hunt in hunts {
        let headers = headers
            .entry(&hunt.group)
            .or_insert((vec![], HashSet::new()));
        // NOTE: We only support count in aggs atm so we can inject that value in...!
        if hunt.is_aggregation() {
            (headers).0.push("count".to_owned());
            (headers).1.insert("count".to_owned());
        }
        for field in hunt.mapper.fields() {
            if field.visible && !headers.1.contains(&field.name) {
                headers.0.push(field.name.clone());
                headers.1.insert(field.name.clone());
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
            let hits = hits.entry((&hunt.group, &hit.timestamp)).or_default();
            (*hits).push(Hit { hunt, rule });
        }
        for ((group, timestamp), mut hits) in hits {
            hits.sort_by(|x, y| x.rule.name().cmp(y.rule.name()));
            let groups = groups.entry(group).or_default();
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
            let mut cells = vec!["timestamp", "detections", "path"];
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
                    timezone.from_utc_datetime(grouping.timestamp).to_rfc3339()
                } else if local {
                    Local.from_utc_datetime(grouping.timestamp).to_rfc3339()
                } else {
                    Utc.from_utc_datetime(grouping.timestamp).to_rfc3339()
                };

                let agg;
                let count;
                let document = match grouping.kind {
                    Kind::Individual { document } => {
                        count = 1;
                        document
                    }
                    Kind::Aggregate { documents } => {
                        count = documents.len();
                        let hunts = grouping.hits.iter().map(|h| h.hunt).collect::<Vec<_>>();
                        agg = agg_to_doc(&hunts, documents)?;
                        &agg
                    }
                    _ => unimplemented!(),
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
                        let data: Value;
                        let wrapper;
                        let mapped = match &document.kind {
                            FileKind::Evtx => {
                                data = bincode::deserialize::<Value>(&document.data)?;
                                wrapper = crate::evtx::Wrapper(&data);
                                hit.hunt.mapper.mapped(&wrapper)
                            }
                            FileKind::Hve
                            | FileKind::Esedb
                            | FileKind::Json
                            | FileKind::Jsonl
                            | FileKind::Mft
                            | FileKind::Xml => {
                                data = bincode::deserialize::<Value>(&document.data)?;
                                hit.hunt.mapper.mapped(&data)
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
                        let rules = seen.entry(id).or_default();
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
                    cells.push(document.path.to_string_lossy().to_string());
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
    pub kind: &'a Kind<'a>,
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
                    timezone.from_utc_datetime(&hit.timestamp).to_rfc3339()
                } else if local {
                    Local.from_utc_datetime(&hit.timestamp).to_rfc3339()
                } else {
                    Utc.from_utc_datetime(&hit.timestamp).to_rfc3339()
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

pub fn print_jsonl(
    detections: &[Detections],
    hunts: &[Hunt],
    rules: &BTreeMap<Uuid, Rule>,
    local: bool,
    timezone: Option<Tz>,
    cache: Option<fs::File>,
) -> crate::Result<()> {
    let hunts: HashMap<_, _> = hunts.iter().map(|h| (&h.id, h)).collect();
    let mut hits: Vec<(_, _, _)> = detections
        .iter()
        .flat_map(|d| {
            let mut scratch = Vec::with_capacity(d.hits.len());
            for hit in &d.hits {
                let localised = if let Some(timezone) = timezone {
                    timezone.from_utc_datetime(&hit.timestamp).to_rfc3339()
                } else if local {
                    Local.from_utc_datetime(&hit.timestamp).to_rfc3339()
                } else {
                    Utc.from_utc_datetime(&hit.timestamp).to_rfc3339()
                };
                scratch.push((localised, hit, d));
            }
            scratch
        })
        .collect();
    hits.sort_by(|x, y| x.0.cmp(&y.0));
    // TODO: Dedupe, maybe just macro it...
    if let Some(cache) = cache.as_ref() {
        let mut f = BufReader::new(cache);
        for (localised, hit, d) in hits {
            let hunt = hunts.get(&hit.hunt).expect("could not get rule!");
            let rule = rules.get(&hit.rule).expect("could not get rule!");
            let det = match rule {
                Rule::Chainsaw(c) => Detection {
                    authors: &c.authors,
                    group: &hunt.group,
                    kind: &d.kind,
                    level: &c.level,
                    name: &c.name,
                    source: RuleKind::Chainsaw,
                    status: &c.status,
                    timestamp: localised,

                    sigma: None,
                },
                Rule::Sigma(s) => {
                    let sigma = Sigma {
                        falsepositives: &s.falsepositives,
                        id: &s.id,
                        logsource: &s.logsource,
                        references: &s.references,
                        tags: &s.tags,
                    };
                    Detection {
                        authors: &s.authors,
                        group: &hunt.group,
                        kind: &d.kind,
                        level: &s.level,
                        name: &s.name,
                        source: RuleKind::Sigma,
                        status: &s.status,
                        timestamp: localised,

                        sigma: Some(sigma),
                    }
                }
            };
            match det.kind {
                Kind::Cached {
                    document,
                    offset,
                    size,
                } => {
                    let _ = f.seek(SeekFrom::Start(*offset as u64));
                    let mut buf = vec![0u8; *size];
                    f.read_exact(&mut buf).expect("could not read cached data");
                    let data = String::from_utf8(buf).expect("could not convert cached data");
                    let raw = RawValue::from_string(data).expect("could not serialize cached data");
                    let kind = Kind::Cached {
                        document: crate::hunt::RawDocument {
                            kind: document.kind.clone(),
                            path: document.path,
                            data: Some(&*raw),
                        },
                        offset: *offset,
                        size: *size,
                    };

                    cs_print_json!(&Detection {
                        authors: det.authors,
                        group: det.group,
                        kind: &kind,
                        level: det.level,
                        name: det.name,
                        source: det.source,
                        status: det.status,
                        timestamp: det.timestamp,
                        sigma: det.sigma,
                    })?;
                }
                _ => {
                    cs_print_json!(&det)?;
                }
            }
            cs_println!();
        }
    } else {
        for (localised, hit, d) in hits {
            let hunt = hunts.get(&hit.hunt).expect("could not get rule!");
            let rule = rules.get(&hit.rule).expect("could not get rule!");
            let det = match rule {
                Rule::Chainsaw(c) => Detection {
                    authors: &c.authors,
                    group: &hunt.group,
                    kind: &d.kind,
                    level: &c.level,
                    name: &c.name,
                    source: RuleKind::Chainsaw,
                    status: &c.status,
                    timestamp: localised,

                    sigma: None,
                },
                Rule::Sigma(s) => {
                    let sigma = Sigma {
                        falsepositives: &s.falsepositives,
                        id: &s.id,
                        logsource: &s.logsource,
                        references: &s.references,
                        tags: &s.tags,
                    };
                    Detection {
                        authors: &s.authors,
                        group: &hunt.group,
                        kind: &d.kind,
                        level: &s.level,
                        name: &s.name,
                        source: RuleKind::Sigma,
                        status: &s.status,
                        timestamp: localised,

                        sigma: Some(sigma),
                    }
                }
            };
            cs_print_json!(&det)?;
            cs_println!();
        }
    }
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
