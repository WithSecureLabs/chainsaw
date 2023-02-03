use std::{path::Path, time};

use anyhow::{Result};
use chrono::{DateTime, Utc};
use regex::Regex;

use crate::file::hve::{
    InventoryApplicationFileArtifact as FileArtifact,
    ShimCacheEntry,
    Parser as HveParser,
    ProgramType
};

#[derive(Debug, Clone)]
enum TimeLineTimestamp {
    Exact(DateTime<Utc>),
    Range(DateTime<Utc>, DateTime<Utc>), // (from, to)
    RangeStart(DateTime<Utc>),
    RangeEnd(DateTime<Utc>),
}

#[derive(Debug)]
struct TimelineEntity<'a> {
    shimcache_entry: &'a ShimCacheEntry,
    amcache_entry: Option<&'a FileArtifact>,
    timestamp: Option<TimeLineTimestamp>,
    amcache_ts_match: bool,
}

impl<'a> TimelineEntity<'a> {
    fn new(shimcache_entry: &'a ShimCacheEntry) -> Self {
        Self {
            shimcache_entry,
            amcache_entry: None,
            timestamp: None,
            amcache_ts_match: false,
        }
    }
}

fn amcache_shimcache_timeline(amcache_path: &str, shimcache_path: &str) -> Result<Option<()>> {
    let mut amcache_parser = HveParser::load(&Path::new(amcache_path))?;
    let mut shimcache_parser = HveParser::load(&Path::new(shimcache_path))?;

    let amcache = amcache_parser.parse_amcache()?;
    let shimcache = shimcache_parser.parse_shimcache()?;

    //TODO: load from a config file instead
    const config_patterns: [&str; 1] = [
        r"[Pp]atch",
    ];
    let regexes = config_patterns.map(|p| Regex::new(p).unwrap());

    // Create timeline entities from shimcache entities
    let mut timeline_entities: Vec<Box<TimelineEntity>> = shimcache.iter().map(
        |e| Box::new(TimelineEntity::new(&e))).collect();

    // Check for matches with config patterns and set timestamp
    let mut match_indices: Vec<usize> = Vec::new();
    for (i, entity) in timeline_entities.iter_mut().enumerate() {
        for re in &regexes {
            let pattern_matches = match &entity.shimcache_entry.program {
                ProgramType::Executable { path, .. } => re.is_match(&path),
                ProgramType::Program { program_name, ..} => re.is_match(&program_name),
            };
            if pattern_matches {
                if let Some(ts) = entity.shimcache_entry.last_modified_ts {
                    entity.timestamp = Some(TimeLineTimestamp::Exact(ts.clone()));
                    match_indices.push(i);
                }
                break;
            }
        }
    }
    if match_indices.is_empty() {
        return Ok(None);
    }

    // Set timestamp ranges for timeline entities based on shimcache entry order
    let first_index = *match_indices.first().unwrap();
    if first_index > 0 {
        let entity = &timeline_entities[first_index];
        let ts = TimeLineTimestamp::RangeStart(entity.shimcache_entry.last_modified_ts.unwrap());
        let first_range = 0usize..first_index;
        for i in first_range {
            timeline_entities[i].timestamp = Some(ts.clone());
        }
    }
    for pair in match_indices.windows(2) {
        let start_i = pair[0];
        let end_i = pair[1];
        let start_entity = &timeline_entities[start_i];
        let end_entity = &timeline_entities[end_i];
        let ts = TimeLineTimestamp::Range(
            end_entity.shimcache_entry.last_modified_ts.unwrap(),
            start_entity.shimcache_entry.last_modified_ts.unwrap()
        );
        let range = start_i+1..end_i;
        for i in range {
            timeline_entities[i].timestamp = Some(ts.clone());
        }
    }
    let last_index = *match_indices.last().unwrap();
    if last_index+1 < timeline_entities.len() {
        let entity = &timeline_entities[last_index];
        let ts = TimeLineTimestamp::RangeEnd(entity.shimcache_entry.last_modified_ts.unwrap());
        let last_range = last_index+1..timeline_entities.len();
        for i in last_range {
            timeline_entities[i].timestamp = Some(ts.clone());
        }
    }

    // Match shimcache and amcache entries and 
    // check if amcache timestamp matches timeline timestamp range
    for file in amcache.iter_files() {
        for mut entity in &mut timeline_entities {
            match &entity.shimcache_entry.program {
                ProgramType::Executable { path } => {
                    if file.path == path.to_lowercase() {
                        entity.amcache_entry = Some(file);
                        if let Some(TimeLineTimestamp::Range(from, to)) = entity.timestamp {
                            let amcache_ts = file.last_modified_ts;
                            if from < amcache_ts && amcache_ts < to {
                                entity.amcache_ts_match = true;
                                entity.timestamp = Some(TimeLineTimestamp::Exact(amcache_ts));
                            }
                        }
                    }
                },
                //TODO: parse also ProgramType::Program type
                ProgramType::Program { .. } => (),
            }
        }
    }

    for entity in timeline_entities {
        println!("{};{:?};{:?};{:?}", entity.shimcache_entry.cache_entry_position, entity.amcache_ts_match, entity.timestamp, entity.shimcache_entry.program);
    }

    Ok(Some(()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combine_shimcache_amcache() -> Result<()> {
        amcache_shimcache_timeline(
            "/mnt/hgfs/vm_shared/win10_vm_hives/am/Amcache.hve",
            "/mnt/hgfs/vm_shared/win10_vm_hives/shim/SYSTEM"
        )?;
        Ok(())
    }
}