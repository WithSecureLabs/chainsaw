use std::{path::{PathBuf}, fs::{File, self}, io::{BufReader, BufRead}};

use anyhow::{Result};
use chrono::{DateTime, Utc, SecondsFormat};
use regex::Regex;

use crate::file::hve::{
    InventoryApplicationFileArtifact as FileArtifact,
    ShimCacheEntry,
    Parser as HveParser,
    ProgramType
};

#[derive(Debug, Clone)]
enum TimelineTimestamp {
    Exact(DateTime<Utc>),
    Range(DateTime<Utc>, DateTime<Utc>), // (from, to)
    RangeStart(DateTime<Utc>),
    RangeEnd(DateTime<Utc>),
}

#[derive(Debug)]
pub struct TimelineEntity {
    shimcache_entry: ShimCacheEntry,
    amcache_file: Option<FileArtifact>,
    timestamp: Option<TimelineTimestamp>,
    amcache_ts_match: bool,
}

impl TimelineEntity {
    fn new(shimcache_entry: ShimCacheEntry) -> Self {
        Self {
            shimcache_entry,
            amcache_file: None,
            timestamp: None,
            amcache_ts_match: false,
        }
    }
}

pub struct Timeliner {
    amcache_path: PathBuf,
    shimcache_path: PathBuf,
}

impl Timeliner {

    pub fn new(amcache_path: PathBuf, shimcache_path: PathBuf) -> Self {
        Self {
            amcache_path,
            shimcache_path
        }
    }

    pub fn amcache_shimcache_timeline(&self, config_path: &PathBuf) -> Result<Option<Vec<TimelineEntity>>> {
        let mut amcache_parser = HveParser::load(&self.amcache_path)?;
        cs_eprintln!("[+] Amcache hive file loaded from {:?}", fs::canonicalize(&self.amcache_path).unwrap());
        let mut shimcache_parser = HveParser::load(&self.shimcache_path)?;
        cs_eprintln!("[+] Shimcache hive file loaded from {:?}", fs::canonicalize(&self.shimcache_path).unwrap());
        let config_patterns = BufReader::new(File::open(config_path)?)
            .lines().collect::<Result<Vec<_>, _>>()?;
    
        let amcache = amcache_parser.parse_amcache()?;
        let shimcache = shimcache_parser.parse_shimcache()?;
    
        let regexes: Vec<Regex> = config_patterns.iter().map(|p| Regex::new(p).unwrap()).collect();
        cs_eprintln!("[+] Config file with {} pattern(s) loaded from {:?}", regexes.len(), fs::canonicalize(&config_path).unwrap());
    
        // Create timeline entities from shimcache entities
        let mut timeline_entities: Vec<TimelineEntity> = shimcache.into_iter().map(
            |e| TimelineEntity::new(e)
        ).collect();
    
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
                        entity.timestamp = Some(TimelineTimestamp::Exact(ts.clone()));
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
    
        fn extract_ts_from_entity(entity: &TimelineEntity) -> DateTime<Utc> {
            match entity.timestamp {
                Some(TimelineTimestamp::Exact(timestamp)) => timestamp,
                _ => panic!("Provided entities should only have exact timestamps!"),
            }
        }
    
        fn set_timestamp_ranges(range_indices: &Vec<usize>, timeline_entities: &mut Vec<TimelineEntity>) {
            // Set timestamp ranges for timeline entities based on shimcache entry order
            let first_index = *range_indices.first().unwrap();
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
                let ts = TimelineTimestamp::Range(
                    extract_ts_from_entity(end_entity),
                    extract_ts_from_entity(start_entity)
                );
                let range = start_i+1..end_i;
                for i in range {
                    timeline_entities[i].timestamp = Some(ts.clone());
                }
            }
            let last_index = *range_indices.last().unwrap();
            if last_index+1 < timeline_entities.len() {
                let entity = &timeline_entities[last_index];
                let ts = TimelineTimestamp::RangeEnd(extract_ts_from_entity(entity));
                let last_range = last_index+1..timeline_entities.len();
                for i in last_range {
                    timeline_entities[i].timestamp = Some(ts.clone());
                }
            }
        }
    
        // Set timestamp ranges for timeline entities based on shimcache entry order
        set_timestamp_ranges(&match_indices, &mut timeline_entities);
    
        // Match shimcache and amcache entries and 
        // check if amcache timestamp matches timeline timestamp range
        for file in amcache.iter_files() {
            for mut entity in &mut timeline_entities {
                match &entity.shimcache_entry.program {
                    ProgramType::Executable { path } => {
                        if file.path == path.to_lowercase() {
                            entity.amcache_file = Some(file.clone());
                            if let Some(TimelineTimestamp::Range(from, to)) = entity.timestamp {
                                let amcache_ts = file.last_modified_ts;
                                if from < amcache_ts && amcache_ts < to {
                                    entity.amcache_ts_match = true;
                                    entity.timestamp = Some(TimelineTimestamp::Exact(amcache_ts));
                                }
                            }
                        }
                    },
                    ProgramType::Program { .. } => (),
                }
            }
        }
        for (_program_id, program) in amcache.programs {
            if let Some(application) = program.application_artifact {
                for mut entity in &mut timeline_entities {
                    match &entity.shimcache_entry.program {
                        ProgramType::Executable { .. } => (),
                        ProgramType::Program { program_name, .. } => {
                            if program_name == &application.program_name {
                                //TODO: link amcache program to timeline entity
                                if let Some(TimelineTimestamp::Range(from, to)) = entity.timestamp {
                                    let amcache_ts = application.last_modified_ts;
                                    if from < amcache_ts && amcache_ts < to {
                                        entity.amcache_ts_match = true;
                                        entity.timestamp = Some(TimelineTimestamp::Exact(amcache_ts));
                                    }
                                }
                            }
                        },
                    }
                }
            }
        }
    
        // Refine timestamp ranges based on amcache matches
        for (i, entity) in timeline_entities.iter_mut().enumerate() {
            if entity.amcache_ts_match {
                match_indices.push(i);
            }
        }
        match_indices.sort();
        set_timestamp_ranges(&match_indices, &mut timeline_entities);
    
        Ok(Some(timeline_entities))
    }

    pub fn output_timeline_csv(timeline: &Vec<TimelineEntity>) {
        cs_println!("timestamp;timestamp description;evidence type;shimcache entry position;shimcache timestamp;amcache timestamp;entry details");
        for entity in timeline {
            let timestamp: String;
            let ts_description: &str;
            let entry_details: String;
            let shimcache_entry_pos: u32;
            let shimcache_timestamp: String;
            let amcache_timestamp: String;
    
            timestamp = match entity.timestamp {
                Some(TimelineTimestamp::Exact(ts)) => ts.to_rfc3339_opts(SecondsFormat::AutoSi, true),
                _ => String::new(),
            };
            ts_description = if entity.amcache_ts_match {
                "Execution timestamp match with amcache"
            } else if let Some(TimelineTimestamp::Exact(_ts)) = entity.timestamp {
                "Shimcache compile timestamp"
            } else { "" };
            shimcache_entry_pos = entity.shimcache_entry.cache_entry_position;
            shimcache_timestamp = if let Some(ts) = entity.shimcache_entry.last_modified_ts {
                ts.to_rfc3339_opts(SecondsFormat::AutoSi, true)
            } else { String::new() };
            amcache_timestamp = if let Some(file) = &entity.amcache_file {
                file.last_modified_ts.to_rfc3339_opts(SecondsFormat::AutoSi, true)
            } else { String::new() };
    
            entry_details = if !entity.amcache_file.is_none() {
                format!("{:?}", &entity.amcache_file.as_ref().unwrap())
            } else {
                format!("{:?}", entity.shimcache_entry.program)
            };
    
            cs_println!("{};{};shimcache;{};{};{};{}",
                timestamp,
                ts_description,
                shimcache_entry_pos,
                shimcache_timestamp,
                amcache_timestamp,
                entry_details,
            );
    
            if entity.amcache_ts_match {
                cs_println!("{timestamp};amcache timestamp;amcache;;;{timestamp};");
            }
        }
    }
}
