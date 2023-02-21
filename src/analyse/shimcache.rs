use std::{path::{PathBuf}, fs::{self}};

use anyhow::{Result};
use chrono::{DateTime, Utc};
use regex::Regex;

use crate::file::hve::{
    amcache::{AmcacheArtifact, FileEntry, ProgramEntry},
    Parser as HveParser,
    shimcache::{EntryType, ShimcacheEntry},
};

#[derive(Debug, Clone)]
pub enum TimelineTimestamp {
    Exact(DateTime<Utc>),
    Range { from: DateTime<Utc>, to: DateTime<Utc> },
    RangeEnd(DateTime<Utc>),
    RangeStart(DateTime<Utc>),
}

#[derive(Debug)]
pub struct TimelineEntity {
    pub amcache_file: Option<FileEntry>,
    pub amcache_program: Option<ProgramEntry>,
    pub amcache_ts_match: bool,
    pub shimcache_entry: Option<ShimcacheEntry>,
    pub timestamp: Option<TimelineTimestamp>,
}

impl TimelineEntity {
    fn with_shimcache_entry(shimcache_entry: ShimcacheEntry) -> Self {
        Self {
            amcache_file: None,
            amcache_program: None,
            amcache_ts_match: false,
            shimcache_entry: Some(shimcache_entry),
            timestamp: None,
        }
    }
}

pub struct ShimcacheAnalyzer {
    amcache_path: Option<PathBuf>,
    shimcache_path: PathBuf,
}

impl ShimcacheAnalyzer {
    pub fn new(shimcache_path: PathBuf, amcache_path: Option<PathBuf>) -> Self {
        Self {
            amcache_path,
            shimcache_path,
        }
    }

    pub fn amcache_shimcache_timeline(&self, regex_patterns: &Vec<String>) -> Result<Option<Vec<TimelineEntity>>> {
        if regex_patterns.is_empty() {
            bail!("No regex patterns defined!")
        }
        let regexes: Vec<Regex> = regex_patterns.iter()
            .map(|p| Regex::new(p)).collect::<Result<Vec<_>,_>>()?;

        let mut shimcache_parser = HveParser::load(&self.shimcache_path)?;
        let shimcache = shimcache_parser.parse_shimcache()?;
        cs_eprintln!("[+] {} shimcache hive file loaded from {:?}", shimcache.version,
            fs::canonicalize(&self.shimcache_path).expect("cloud not get absolute path"));

        let amcache: Option<AmcacheArtifact> = if let Some(amcache_path) = &self.amcache_path {
            let mut amcache_parser = HveParser::load(&amcache_path)?;
            Some(amcache_parser.parse_amcache()?)
        } else {
            None
        };
        if let Some(amcache_path) = &self.amcache_path {
            cs_eprintln!("[+] Amcache hive file loaded from {:?}", fs::canonicalize(amcache_path)
                .expect("cloud not get absolute path"));
        }

        // Create timeline entities from shimcache entities
        let mut timeline_entities: Vec<TimelineEntity> = shimcache.entries.into_iter().map(
            |e| TimelineEntity::with_shimcache_entry(e)
        ).collect();
        // Prepend the shimcache last update timestamp as the first timeline entity
        timeline_entities.insert(0, TimelineEntity {
            amcache_file: None,
            amcache_program: None,
            amcache_ts_match: false,
            shimcache_entry: None,
            timestamp: Some(TimelineTimestamp::Exact(shimcache.last_update_ts)),
        });

        let mut match_indices: Vec<usize> = Vec::new();
        // Check for matches with config patterns and set timestamp
        for (i, entity) in timeline_entities.iter_mut().enumerate() {
            for re in &regexes {
                let shimcache_entry = if let Some(entry) = &entity.shimcache_entry {
                    entry
                } else { continue; };
                let pattern_matches = match &shimcache_entry.entry_type {
                    EntryType::File { path, .. } => re.is_match(&path),
                    EntryType::Program { program_name, ..} => re.is_match(&program_name),
                };
                if pattern_matches {
                    if let Some(ts) = shimcache_entry.last_modified_ts {
                        entity.timestamp = Some(TimelineTimestamp::Exact(ts));
                        match_indices.push(i);
                    }
                    break;
                }
            }
        }
        if match_indices.is_empty() {
            // If there were no matches, no additional timeline data can be inferred
            return Ok(None);
        }
        cs_eprintln!("[+] {} matching entries found from shimcache", match_indices.len());
        // Consider the shimcache last update timestamp a match
        match_indices.insert(0, 0);
    
        fn extract_ts_from_entity(entity: &TimelineEntity) -> DateTime<Utc> {
            match entity.timestamp {
                Some(TimelineTimestamp::Exact(timestamp)) => timestamp,
                _ => panic!("Provided entities should only have exact timestamps!"),
            }
        }
    
        /// Sets timestamp ranges for timeline entities based on shimcache entry order
        fn set_timestamp_ranges(range_indices: &Vec<usize>, timeline_entities: &mut Vec<TimelineEntity>) {
            let first_index = *range_indices.first().expect("empty range_indices provided");
            if first_index > 0 {
                let entity = &timeline_entities[first_index];
                let ts = TimelineTimestamp::RangeStart(extract_ts_from_entity(entity));
                let first_range = 0usize..first_index;
                for i in first_range {
                    timeline_entities[i].timestamp = Some(ts.clone());
                }
            }
            for pair in range_indices.windows(2) {
                let start_i = pair[0];
                let end_i = pair[1];
                let start_entity = &timeline_entities[start_i];
                let end_entity = &timeline_entities[end_i];
                let ts = TimelineTimestamp::Range{
                    from: extract_ts_from_entity(end_entity),
                    to: extract_ts_from_entity(start_entity)
                };
                let range = start_i+1..end_i;
                for i in range {
                    timeline_entities[i].timestamp = Some(ts.clone());
                }
            }
            let last_index = *range_indices.last().expect("could not get last vector element");
            if last_index+1 < timeline_entities.len() {
                let entity = &timeline_entities[last_index];
                let ts = TimelineTimestamp::RangeEnd(extract_ts_from_entity(entity));
                let last_range = last_index+1..timeline_entities.len();
                for i in last_range {
                    timeline_entities[i].timestamp = Some(ts.clone());
                }
            }
        }
    
        set_timestamp_ranges(&match_indices, &mut timeline_entities);
    
        if let Some(amcache) = amcache {
            // Match shimcache and amcache entries and 
            // check if amcache timestamp matches timeline timestamp range
            let mut ts_match_count = 0;
            for file_entry in amcache.file_entries.into_iter() {
                for mut entity in &mut timeline_entities {
                    let shimcache_entry = if let Some(entry) = &entity.shimcache_entry {
                        entry
                    } else { continue; };
                    match &shimcache_entry.entry_type {
                        EntryType::File { path } => {
                            if file_entry.path == path.to_lowercase() {
                                let amcache_ts = file_entry.key_last_modified_ts.clone();
                                entity.amcache_file = Some(file_entry);
                                if let Some(TimelineTimestamp::Range{from, to}) = entity.timestamp {
                                    if from < amcache_ts && amcache_ts < to {
                                        entity.amcache_ts_match = true;
                                        entity.timestamp = Some(TimelineTimestamp::Exact(amcache_ts));
                                        ts_match_count += 1;
                                    }
                                }
                                // Assume there are no two shimcache entries with the same path
                                break;
                            }
                        },
                        EntryType::Program { .. } => (),
                    }
                }
            }
            for program_entry in amcache.program_entries.into_iter() {
                for mut entity in &mut timeline_entities {
                    let shimcache_entry = if let Some(shimcache_entry) = &entity.shimcache_entry {
                        shimcache_entry
                    } else { continue; };
                    match &shimcache_entry.entry_type {
                        EntryType::File { .. } => (),
                        EntryType::Program { program_name, .. } => {
                            if program_name == &program_entry.program_name {
                                if let Some(TimelineTimestamp::Range{from, to}) = entity.timestamp {
                                    let amcache_ts = program_entry.last_modified_ts.clone();
                                    entity.amcache_program = Some(program_entry);
                                    if from < amcache_ts && amcache_ts < to {
                                        entity.amcache_ts_match = true;
                                        entity.timestamp = Some(TimelineTimestamp::Exact(amcache_ts));
                                        ts_match_count += 1;
                                    }
                                    // Assume there are no two shimcache entries with the same path
                                    break;
                                }
                            }
                        },
                    }
                }
            }
            cs_eprintln!("[+] {} timestamp range matches found from amcache", ts_match_count);
        
            // Refine timestamp ranges based on amcache matches
            for (i, entity) in timeline_entities.iter_mut().enumerate() {
                if entity.amcache_ts_match {
                    match_indices.push(i);
                }
            }
            match_indices.sort();
            set_timestamp_ranges(&match_indices, &mut timeline_entities);
        }
        Ok(Some(timeline_entities))
    }
}
