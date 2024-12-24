use std::io::{BufReader, Write};
use std::path::{self, Path, PathBuf};
use std::{fs::create_dir_all, fs::File, ops::RangeInclusive, str::FromStr};

use anyhow::{anyhow, Error, Result};
use mft::{
    attribute::MftAttributeType,
    csv::FlatMftEntryWithName,
    entry::{MftEntry, ZERO_HEADER},
    MftParser,
};
use serde::Serialize;
use serde_json::{json, Value as Json};

pub type Mft = Json;

pub struct Parser {
    pub inner: MftParser<BufReader<File>>,
    ranges: Option<Ranges>,
    pub data_streams_directory: Option<PathBuf>,
    pub decode_data_streams: bool,
}

#[derive(Serialize)]
struct DataStreams {
    stream_name: String,
    stream_number: usize,
    stream_data: String,
}

struct Ranges(Vec<RangeInclusive<usize>>);

impl Ranges {
    pub fn chain(&self) -> impl Iterator<Item = usize> + '_ {
        self.0.iter().cloned().flatten()
    }
}

impl FromStr for Ranges {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut ranges = vec![];
        for x in s.split(',') {
            // range
            if x.contains('-') {
                let range: Vec<&str> = x.split('-').collect();
                if range.len() != 2 {
                    return Err(anyhow!(
                        "Failed to parse ranges: Range should contain exactly one `-`, found {}",
                        x
                    ));
                }

                ranges.push(range[0].parse()?..=range[1].parse()?);
            } else {
                let n = x.parse()?;
                ranges.push(n..=n);
            }
        }

        Ok(Ranges(ranges))
    }
}

impl Parser {
    pub fn load(
        file: &Path,
        data_streams_directory: Option<PathBuf>,
        decode_data_streams: bool,
    ) -> crate::Result<Self> {
        let parser = MftParser::from_path(file)?;
        Ok(Self {
            inner: parser,
            ranges: None,
            data_streams_directory,
            decode_data_streams,
        })
    }

    pub fn parse(&mut self) -> impl Iterator<Item = crate::Result<Json>> + '_ {
        // Code is adapted MFT Library implementation of the mft_dump.rs file
        // Reference: https://github.com/omerbenamram/mft/blob/6767bb5d3787b5532a7a5a07532f0c6b4e22413d/src/bin/mft_dump.rs#L289

        if let Some(data_streams_dir) = &self.data_streams_directory {
            if !data_streams_dir.exists() {
                create_dir_all(data_streams_dir).expect("Failed to create data streams directory");
            }
        }

        let number_of_entries = self.inner.get_entry_count();

        let take_ranges = self.ranges.take();

        let entries = match take_ranges {
            Some(ref ranges) => Box::new(ranges.chain()),
            None => Box::new(0..number_of_entries as usize) as Box<dyn Iterator<Item = usize>>,
        };

        let collected_entries: Vec<_> = entries
            .filter_map(|i| {
                let entry = self.inner.get_entry(i as u64);
                match entry {
                    Ok(entry) => match &entry.header.signature {
                        // Skip entries with zero headers
                        ZERO_HEADER => None,
                        _ => Some(entry),
                    },
                    Err(error) => {
                        cs_eyellowln!("{}", error);
                        None
                    }
                }
            })
            .collect();

        collected_entries.into_iter().map(|e| {
            // Get the MFT entry base details from the entry using FlatMftEntryWithName
            match serde_json::to_value(FlatMftEntryWithName::from_entry(&e, &mut self.inner)) {
                Ok(mut val) => {
                    // Extract the DataStreams from the MFT entry
                    val["DataStreams"] = extract_data_streams(self, &e)?;
                    Ok(val)
                }
                Err(e) => Err(anyhow::Error::from(e)),
            }
        })
    }
}

pub fn extract_data_streams(parser: &mut Parser, entry: &MftEntry) -> crate::Result<Json> {
    // This function is used to extract the data streams from the MFT entry.
    // It will attempt to write the data streams to the output path if provided.
    // It will attempt to decode the data streams if the decode_data_streams flag is set.

    // Code is based on the MFT Library implementation of the mft_dump.rs file
    // Reference: https://github.com/omerbenamram/mft/blob/6767bb5d3787b5532a7a5a07532f0c6b4e22413d/src/bin/mft_dump.rs#L289

    let mut data_streams = vec![];

    for (i, (name, stream)) in entry
        .iter_attributes()
        .filter_map(|a| a.ok())
        .filter_map(|a| {
            if a.header.type_code == MftAttributeType::DATA {
                let name = a.header.name.clone();
                a.data.into_data().map(|data| (name, data))
            } else {
                None
            }
        })
        .enumerate()
    {
        if let Some(data_streams_dir) = &parser.data_streams_directory {
            if let Some(path) = parser.inner.get_full_path_for_entry(entry)? {
                // Replace file path seperators with underscores

                let sanitized_path = path
                    .to_string_lossy()
                    .chars()
                    .map(|c| if path::is_separator(c) { '_' } else { c })
                    .collect::<String>();

                let output_path: String = data_streams_dir
                    .join(&sanitized_path)
                    .to_string_lossy()
                    .to_string();

                // Generate 6 characters random hex string
                let random: String = (0..6)
                    .map(|_| format!("{:02x}", rand::random::<u8>()))
                    .fold(String::new(), |acc, hex| format!("{}{}", acc, hex));

                let truncated: String = output_path.chars().take(150).collect();

                if PathBuf::from(&output_path).exists() {
                    return Err(anyhow!(
                        "Data stream output path already exists: {}\n\
                        Exiting out of precaution.",
                        output_path
                    ));
                }

                File::create(format!(
                    "{path}__{random}_{stream_number}_{stream_name}.disabled",
                    path = truncated,
                    random = random,
                    stream_number = i,
                    stream_name = name
                ))?
                .write_all(stream.data())?;
            }
        }

        //convert stream.data() to a hex string
        let final_data_stream = if parser.decode_data_streams {
            String::from_utf8_lossy(stream.data()).to_string()
        } else {
            stream
                .data()
                .iter()
                .map(|byte| format!("{:02x}", byte))
                .fold(String::new(), |acc, hex| format!("{}{}", acc, hex))
        };

        data_streams.push(DataStreams {
            stream_name: name,
            stream_number: i,
            stream_data: final_data_stream,
        });
    }
    Ok(json!(data_streams))
}
