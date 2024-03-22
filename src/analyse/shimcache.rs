use std::{fs, path::PathBuf, rc::Rc};

use chrono::{DateTime, Utc};
use regex::Regex;

use crate::file::hve::{
    amcache::{AmcacheArtefact, FileEntry, ProgramEntry},
    shimcache::{EntryType, ShimcacheEntry},
    Parser as HveParser,
};

#[derive(Debug, Clone)]
pub enum TimestampType {
    AmcacheRangeMatch,
    NearTSMatch,
    PatternMatch,
    ShimcacheLastUpdate,
}

#[derive(Debug, Clone)]
pub enum TimelineTimestamp {
    Exact(DateTime<Utc>, TimestampType),
    Range {
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    },
    RangeEnd(DateTime<Utc>),
    RangeStart(DateTime<Utc>),
}

#[derive(Debug)]
pub struct TimelineEntity {
    pub amcache_file: Option<Rc<FileEntry>>,
    pub amcache_program: Option<Rc<ProgramEntry>>,
    pub shimcache_entry: Option<ShimcacheEntry>,
    pub timestamp: Option<TimelineTimestamp>,
}

impl TimelineEntity {
    fn with_shimcache_entry(shimcache_entry: ShimcacheEntry) -> Self {
        Self {
            amcache_file: None,
            amcache_program: None,
            shimcache_entry: Some(shimcache_entry),
            timestamp: None,
        }
    }
}

pub struct ShimcacheAnalyser {
    amcache_path: Option<PathBuf>,
    shimcache_path: PathBuf,
}

impl ShimcacheAnalyser {
    pub fn new(shimcache_path: PathBuf, amcache_path: Option<PathBuf>) -> Self {
        Self {
            amcache_path,
            shimcache_path,
        }
    }

    pub fn amcache_shimcache_timeline(
        &self,
        regex_patterns: &[String],
        ts_near_pair_matching: bool,
    ) -> crate::Result<Vec<TimelineEntity>> {
        if regex_patterns.is_empty() {
            cs_eyellowln!("[!] No regex patterns defined for matching shimcache entries!")
        }
        let regexes: Vec<Regex> = regex_patterns
            .iter()
            .map(|p| Regex::new(p))
            .collect::<Result<Vec<_>, _>>()?;

        // Load shimcache
        let mut shimcache_parser = HveParser::load(&self.shimcache_path)?;
        let shimcache = shimcache_parser.parse_shimcache()?;
        cs_eprintln!(
            "[+] {} shimcache hive file loaded from {:?}",
            shimcache.version,
            fs::canonicalize(&self.shimcache_path).expect("could not get absolute path")
        );

        // Load amcache
        let amcache: Option<AmcacheArtefact> = if let Some(amcache_path) = &self.amcache_path {
            let mut amcache_parser = HveParser::load(amcache_path)?;
            cs_eprintln!(
                "[+] Amcache hive file loaded from {:?}",
                fs::canonicalize(amcache_path).expect("could not get absolute path")
            );
            Some(amcache_parser.parse_amcache()?)
        } else {
            None
        };

        fn extract_ts_from_entity(entity: &TimelineEntity) -> DateTime<Utc> {
            match &entity.timestamp {
                Some(TimelineTimestamp::Exact(timestamp, _type)) => *timestamp,
                _ => unimplemented!("Provided entities should only have exact timestamps!"),
            }
        }

        /// Gets the indices of timeline entities which have a timestamp of the type Exact
        fn get_exact_ts_indices(timeline_entities: &[TimelineEntity]) -> Vec<usize> {
            let mut indices: Vec<usize> = Vec::new();
            for (i, entity) in timeline_entities.iter().enumerate() {
                if let Some(TimelineTimestamp::Exact(_ts, _type)) = &entity.timestamp {
                    indices.push(i);
                }
            }
            indices
        }

        /// Sets timestamp ranges for timeline entities based on shimcache entry order and indices
        fn set_timestamp_ranges(range_indices: &[usize], timeline_entities: &mut [TimelineEntity]) {
            let first_index = if let Some(index) = range_indices.first() {
                *index
            } else {
                return;
            };
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
                let ts = TimelineTimestamp::Range {
                    from: extract_ts_from_entity(end_entity),
                    to: extract_ts_from_entity(start_entity),
                };
                let range = start_i + 1..end_i;
                for i in range {
                    timeline_entities[i].timestamp = Some(ts.clone());
                }
            }
            let last_index = *range_indices
                .last()
                .expect("could not get last vector element");
            if last_index + 1 < timeline_entities.len() {
                let entity = &timeline_entities[last_index];
                let ts = TimelineTimestamp::RangeEnd(extract_ts_from_entity(entity));
                let last_range = last_index + 1..timeline_entities.len();
                for i in last_range {
                    timeline_entities[i].timestamp = Some(ts.clone());
                }
            }
        }

        // Create timeline entities from shimcache entities
        let mut timeline_entities: Vec<TimelineEntity> = shimcache
            .entries
            .into_iter()
            .map(TimelineEntity::with_shimcache_entry)
            .collect();
        // Prepend the shimcache last update timestamp as the first timeline entity
        timeline_entities.insert(
            0,
            TimelineEntity {
                amcache_file: None,
                amcache_program: None,
                shimcache_entry: None,
                timestamp: Some(TimelineTimestamp::Exact(
                    shimcache.last_update_ts,
                    TimestampType::ShimcacheLastUpdate,
                )),
            },
        );

        let mut pattern_match_count = 0;
        // Check for matches with config patterns and set timestamp
        for entity in timeline_entities.iter_mut() {
            for re in &regexes {
                let shimcache_entry = if let Some(entry) = &entity.shimcache_entry {
                    entry
                } else {
                    continue;
                };
                let pattern_matches = match &shimcache_entry.entry_type {
                    EntryType::File { path, .. } => re.is_match(&path.to_lowercase()),
                    EntryType::Program { .. } => false,
                };
                if pattern_matches {
                    if let Some(ts) = shimcache_entry.last_modified_ts {
                        entity.timestamp =
                            Some(TimelineTimestamp::Exact(ts, TimestampType::PatternMatch));
                        pattern_match_count += 1;
                    }
                    break;
                }
            }
        }
        if pattern_match_count == 0 {
            cs_eyellowln!("[!] 0 pattern matching entries found from shimcache")
        } else {
            cs_eprintln!(
                "[+] {} pattern matching entries found from shimcache",
                pattern_match_count
            );
        }

        // Set timestamp ranges based on regex matched entries
        set_timestamp_ranges(
            &get_exact_ts_indices(&timeline_entities),
            &mut timeline_entities,
        );

        // Amcache enrichments
        if let Some(amcache) = amcache {
            // Match shimcache and amcache file entries
            for file_entry in amcache.file_entries.into_iter() {
                let file_entry = Rc::new(file_entry);
                for entity in &mut timeline_entities {
                    let shimcache_entry = if let Some(entry) = &entity.shimcache_entry {
                        entry
                    } else {
                        continue;
                    };
                    if let EntryType::File { path } = &shimcache_entry.entry_type {
                        if file_entry.path.to_lowercase() == path.to_lowercase() {
                            entity.amcache_file = Some(Rc::clone(&file_entry));
                        }
                    }
                }
            }

            // Match shimcache and amcache program entries
            for program_entry in amcache.program_entries.into_iter() {
                let program_entry = Rc::new(program_entry);
                for entity in &mut timeline_entities {
                    let shimcache_entry = if let Some(entry) = &entity.shimcache_entry {
                        entry
                    } else {
                        continue;
                    };
                    if let EntryType::Program {
                        program_name,
                        program_version,
                        ..
                    } = &shimcache_entry.entry_type
                    {
                        if &program_entry.program_name == program_name
                            && &program_entry.version == program_version
                        {
                            entity.amcache_program = Some(Rc::clone(&program_entry));
                        }
                    }
                }
            }

            if ts_near_pair_matching {
                // Find near Amcache and Shimcache timestamp pairs
                const MAX_TIME_DIFFERENCE: i64 = 60 * 1000; // 1 min
                let mut near_timestamps_count = 0;
                let mut pattern_match_overlap_count = 0;
                for entity in &mut timeline_entities {
                    if let (Some(shimcache_entry), Some(amcache_entry)) =
                        (&entity.shimcache_entry, &entity.amcache_file)
                    {
                        if let Some(shimcache_ts) = shimcache_entry.last_modified_ts {
                            let difference = shimcache_ts - amcache_entry.key_last_modified_ts;
                            if difference.num_milliseconds().abs() > MAX_TIME_DIFFERENCE {
                                continue;
                            }
                            near_timestamps_count += 1;
                            // Do not overwrite pattern matched timestamps
                            if let Some(TimelineTimestamp::Exact(
                                _ts,
                                TimestampType::PatternMatch,
                            )) = entity.timestamp
                            {
                                pattern_match_overlap_count += 1;
                                continue;
                            }
                            entity.timestamp = Some(TimelineTimestamp::Exact(
                                amcache_entry.key_last_modified_ts,
                                TimestampType::NearTSMatch,
                            ));
                        }
                    }
                }
                let new_exact_ts_indices = get_exact_ts_indices(&timeline_entities);
                cs_eprintln!(
                    "[+] {} near shimcache & amcache timestamp pairs found (with {} overlapping the pattern matched entries)",
                    near_timestamps_count,
                    pattern_match_overlap_count,
                );

                // Set timestamp ranges again, including Amcache & Shimcache timestamp near pairs
                set_timestamp_ranges(&new_exact_ts_indices, &mut timeline_entities);
            }

            // Find amcache entries whose timestamp corresponds to entity ts range
            let mut ts_match_count = 0;
            for entity in &mut timeline_entities {
                let shimcache_entry = if let Some(entry) = &entity.shimcache_entry {
                    entry
                } else {
                    continue;
                };
                let amcache_file_entry = if let Some(entry) = &entity.amcache_file {
                    entry
                } else {
                    continue;
                };
                if let EntryType::File { .. } = &shimcache_entry.entry_type {
                    if let Some(TimelineTimestamp::Range { from, to }) = entity.timestamp {
                        let amcache_ts = amcache_file_entry.key_last_modified_ts;
                        if from < amcache_ts && amcache_ts < to {
                            entity.timestamp = Some(TimelineTimestamp::Exact(
                                amcache_ts,
                                TimestampType::AmcacheRangeMatch,
                            ));
                            ts_match_count += 1;
                        }
                    }
                }
            }
            cs_eprintln!(
                "[+] {} timestamp range matches found from amcache",
                ts_match_count
            );

            // Refine timestamp ranges based on entity ts range matches
            set_timestamp_ranges(
                &get_exact_ts_indices(&timeline_entities),
                &mut timeline_entities,
            );
        }
        Ok(timeline_entities)
    }
}
