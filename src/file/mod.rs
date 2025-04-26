use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};

use chrono::{DateTime, Utc};

use self::esedb::{Esedb, Parser as EsedbParser};
use self::evtx::{Evtx, Parser as EvtxParser};
use self::hve::{Hve, Parser as HveParser};
use self::json::{Json, Parser as JsonParser, lines::Parser as JsonlParser};
use self::mft::{Mft, Parser as MftParser};
use self::xml::{Parser as XmlParser, Xml};

use flate2::read::GzDecoder;
use std::fs::File;
use std::io::BufReader;

pub mod esedb;
pub mod evtx;
pub mod hve;
pub mod json;
pub mod mft;
pub mod xml;

#[derive(Clone)]
pub enum Document {
    Evtx(Evtx),
    Hve(Hve),
    Json(Json),
    Mft(Mft),
    Xml(Xml),
    Esedb(Esedb),
}

pub struct Documents<'a> {
    iterator: Box<dyn Iterator<Item = crate::Result<Document>> + Send + Sync + 'a>,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, Hash, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Evtx,
    Hve,
    Json,
    Jsonl,
    Mft,
    Xml,
    Esedb,
    Unknown,
}

impl Kind {
    pub fn extensions(&self) -> Option<Vec<String>> {
        match self {
            Kind::Evtx => Some(vec![
                "evt".to_string(),
                "evtx".to_string(),
                "gz".to_string(),
            ]),
            Kind::Hve => Some(vec!["hve".to_string()]),
            Kind::Json => Some(vec!["json".to_string(), "gz".to_string()]),
            Kind::Jsonl => Some(vec!["jsonl".to_string(), "gz".to_string()]),
            Kind::Mft => Some(vec![
                "mft".to_string(),
                "bin".to_string(),
                "$MFT".to_string(),
            ]),
            Kind::Xml => Some(vec!["xml".to_string()]),
            Kind::Esedb => Some(vec!["dat".to_string(), "edb".to_string()]),
            Kind::Unknown => None,
        }
    }
}

impl Iterator for Documents<'_> {
    type Item = crate::Result<Document>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iterator.next()
    }
}

pub struct Unknown;
impl Iterator for Unknown {
    type Item = crate::Result<Document>;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

#[allow(clippy::large_enum_variant)]
pub enum Parser {
    Evtx(EvtxParser),
    Hve(HveParser),
    Json(JsonParser),
    Jsonl(JsonlParser),
    Mft(MftParser),
    Xml(XmlParser),
    Esedb(EsedbParser),
    Unknown,
}

pub struct Reader {
    parser: Parser,
}

impl Reader {
    pub fn load(
        file: &Path,
        load_unknown: bool,
        skip_errors: bool,
        decode_data_streams: bool,
        data_streams_directory: Option<PathBuf>,
        decoder: Option<GzDecoder<BufReader<File>>>,
    ) -> crate::Result<Self> {
        // NOTE: We don't want to use libmagic because then we have to include databases etc... So
        // for now we assume that the file extensions are correct!
        match file.extension().and_then(|e| e.to_str()) {
            Some(extension) => match extension {
                "gz" => {
                    // If a .gz file is passed then we open it, extract the embedded filename from the header
                    // then pass the GzReader and the filename back to this loader function for parsing.
                    let file_handle = File::open(file)?;
                    let reader = BufReader::new(file_handle);
                    let decoder = GzDecoder::new(reader);

                    // Get the filename of the uncompressed file so we can route to the correct loader
                    let mut filename: String = String::new();
                    let mut failed = false;
                    match decoder.header() {
                        Some(header) => match header.filename() {
                            Some(f) => {
                                filename = String::from_utf8_lossy(f).to_string();
                            }
                            None => {
                                failed = true;
                            }
                        },
                        None => {
                            failed = true;
                        }
                    }
                    if failed {
                        if skip_errors {
                            cs_eyellowln!(
                                "[!] Failed to get filename from gzip header - {}",
                                file.display()
                            );
                            return Ok(Self {
                                parser: Parser::Unknown,
                            });
                        }
                        anyhow::bail!(
                            "Failed to get filename from gzip header - {}",
                            file.display()
                        );
                    }
                    let parser = Reader::load(
                        Path::new(&filename.to_owned()),
                        load_unknown,
                        skip_errors,
                        decode_data_streams,
                        data_streams_directory,
                        Some(decoder),
                    )?;
                    return Ok(parser);
                }
                "evt" | "evtx" => {
                    let parser = match EvtxParser::load(file, decoder) {
                        Ok(parser) => parser,
                        Err(e) => {
                            if skip_errors {
                                cs_eyellowln!(
                                    "[!] failed to load file '{}' - {}\n",
                                    file.display(),
                                    e
                                );
                                return Ok(Self {
                                    parser: Parser::Unknown,
                                });
                            } else {
                                anyhow::bail!(e);
                            }
                        }
                    };
                    Ok(Self {
                        parser: Parser::Evtx(parser),
                    })
                }
                "json" => {
                    let parser = match JsonParser::load(file, decoder) {
                        Ok(parser) => parser,
                        Err(e) => {
                            if skip_errors {
                                cs_eyellowln!(
                                    "[!] failed to load file '{}' - {}\n",
                                    file.display(),
                                    e
                                );
                                return Ok(Self {
                                    parser: Parser::Unknown,
                                });
                            } else {
                                anyhow::bail!(e);
                            }
                        }
                    };
                    Ok(Self {
                        parser: Parser::Json(parser),
                    })
                }
                "jsonl" => {
                    let parser = match JsonlParser::load(file, decoder) {
                        Ok(parser) => parser,
                        Err(e) => {
                            if skip_errors {
                                cs_eyellowln!(
                                    "[!] failed to load file '{}' - {}\n",
                                    file.display(),
                                    e
                                );
                                return Ok(Self {
                                    parser: Parser::Unknown,
                                });
                            } else {
                                anyhow::bail!(e);
                            }
                        }
                    };
                    Ok(Self {
                        parser: Parser::Jsonl(parser),
                    })
                }
                "bin" | "mft" => {
                    let parser = match MftParser::load(
                        file,
                        data_streams_directory.clone(),
                        decode_data_streams,
                        decoder,
                    ) {
                        Ok(parser) => parser,
                        Err(e) => {
                            if skip_errors {
                                cs_eyellowln!(
                                    "[!] failed to load file '{}' - {}\n",
                                    file.display(),
                                    e
                                );
                                return Ok(Self {
                                    parser: Parser::Unknown,
                                });
                            } else {
                                anyhow::bail!(e);
                            }
                        }
                    };
                    Ok(Self {
                        parser: Parser::Mft(parser),
                    })
                }
                "xml" => {
                    let parser = match XmlParser::load(file, decoder) {
                        Ok(parser) => parser,
                        Err(e) => {
                            if skip_errors {
                                cs_eyellowln!(
                                    "[!] failed to load file '{}' - {}\n",
                                    file.display(),
                                    e
                                );
                                return Ok(Self {
                                    parser: Parser::Unknown,
                                });
                            } else {
                                anyhow::bail!(e);
                            }
                        }
                    };
                    Ok(Self {
                        parser: Parser::Xml(parser),
                    })
                }
                "hve" => {
                    let parser = match HveParser::load(file) {
                        Ok(parser) => parser,
                        Err(e) => {
                            if skip_errors {
                                cs_eyellowln!(
                                    "[!] failed to load file '{}' - {}\n",
                                    file.display(),
                                    e
                                );
                                return Ok(Self {
                                    parser: Parser::Unknown,
                                });
                            } else {
                                anyhow::bail!(e);
                            }
                        }
                    };
                    Ok(Self {
                        parser: Parser::Hve(parser),
                    })
                }
                "dat" | "edb" => {
                    let parser = match EsedbParser::load(file, decoder) {
                        Ok(parser) => parser,
                        Err(e) => {
                            if skip_errors {
                                cs_eyellowln!(
                                    "[!] failed to load file '{}' - {}\n",
                                    file.display(),
                                    e
                                );
                                return Ok(Self {
                                    parser: Parser::Unknown,
                                });
                            } else {
                                anyhow::bail!(e);
                            }
                        }
                    };
                    Ok(Self {
                        parser: Parser::Esedb(parser),
                    })
                }
                _ => {
                    if load_unknown {
                        if let Ok(parser) = EvtxParser::load(file, decoder) {
                            return Ok(Self {
                                parser: Parser::Evtx(parser),
                            });
                        } else if let Ok(parser) = MftParser::load(
                            file,
                            data_streams_directory.clone(),
                            decode_data_streams,
                            None,
                        ) {
                            return Ok(Self {
                                parser: Parser::Mft(parser),
                            });
                        } else if let Ok(parser) = JsonParser::load(file, None) {
                            return Ok(Self {
                                parser: Parser::Json(parser),
                            });
                        } else if let Ok(parser) = XmlParser::load(file, None) {
                            return Ok(Self {
                                parser: Parser::Xml(parser),
                            });
                        } else if let Ok(parser) = HveParser::load(file) {
                            return Ok(Self {
                                parser: Parser::Hve(parser),
                            });
                        } else if let Ok(parser) = EsedbParser::load(file, None) {
                            return Ok(Self {
                                parser: Parser::Esedb(parser),
                            });
                        }
                        if skip_errors {
                            cs_eyellowln!(
                                "[!] file type is not currently supported - {}\n",
                                file.display()
                            );
                            Ok(Self {
                                parser: Parser::Unknown,
                            })
                        } else {
                            anyhow::bail!(
                                "file type is not currently supported - {}, use --skip-errors to continue...",
                                file.display()
                            )
                        }
                    } else {
                        Ok(Self {
                            parser: Parser::Unknown,
                        })
                    }
                }
            },
            None => {
                // Edge cases
                if file.file_name().and_then(|e| e.to_str()) == Some("$MFT") {
                    if let Ok(parser) = MftParser::load(
                        file,
                        data_streams_directory.clone(),
                        decode_data_streams,
                        decoder,
                    ) {
                        return Ok(Self {
                            parser: Parser::Mft(parser),
                        });
                    }
                }
                if load_unknown {
                    if let Ok(parser) = EvtxParser::load(file, None) {
                        return Ok(Self {
                            parser: Parser::Evtx(parser),
                        });
                    } else if let Ok(parser) = MftParser::load(
                        file,
                        data_streams_directory.clone(),
                        decode_data_streams,
                        None,
                    ) {
                        return Ok(Self {
                            parser: Parser::Mft(parser),
                        });
                    } else if let Ok(parser) = JsonParser::load(file, None) {
                        return Ok(Self {
                            parser: Parser::Json(parser),
                        });
                    } else if let Ok(parser) = XmlParser::load(file, None) {
                        return Ok(Self {
                            parser: Parser::Xml(parser),
                        });
                    } else if let Ok(parser) = HveParser::load(file) {
                        return Ok(Self {
                            parser: Parser::Hve(parser),
                        });
                    } else if let Ok(parser) = EsedbParser::load(file, None) {
                        return Ok(Self {
                            parser: Parser::Esedb(parser),
                        });
                    }
                    // NOTE: We don't support the JSONL parser as it is too generic, maybe we are
                    // happy to use it as the fallback...?
                    if skip_errors {
                        cs_eyellowln!("[!] file type is not known - {}\n", file.display());
                        Ok(Self {
                            parser: Parser::Unknown,
                        })
                    } else {
                        anyhow::bail!(
                            "file type is not known - {}, use --skip-errors to continue...",
                            file.display()
                        )
                    }
                } else {
                    Ok(Self {
                        parser: Parser::Unknown,
                    })
                }
            }
        }
    }

    pub fn documents<'a>(&'a mut self) -> Documents<'a> {
        let iterator = match &mut self.parser {
            Parser::Evtx(parser) => Box::new(
                parser
                    .parse()
                    .map(|r| r.map(Document::Evtx).map_err(|e| e.into())),
            )
                as Box<dyn Iterator<Item = crate::Result<Document>> + Send + Sync + 'a>,
            Parser::Hve(parser) => Box::new(parser.parse().map(|r| r.map(Document::Hve)))
                as Box<dyn Iterator<Item = crate::Result<Document>> + Send + Sync + 'a>,
            Parser::Json(parser) => Box::new(parser.parse().map(|r| r.map(Document::Json)))
                as Box<dyn Iterator<Item = crate::Result<Document>> + Send + Sync + 'a>,
            Parser::Jsonl(parser) => Box::new(parser.parse().map(|r| r.map(Document::Json)))
                as Box<dyn Iterator<Item = crate::Result<Document>> + Send + Sync + 'a>,
            Parser::Mft(parser) => Box::new(parser.parse().map(|r| r.map(Document::Mft)))
                as Box<dyn Iterator<Item = crate::Result<Document>> + Send + Sync + 'a>,
            Parser::Xml(parser) => Box::new(parser.parse().map(|r| r.map(Document::Xml)))
                as Box<dyn Iterator<Item = crate::Result<Document>> + Send + Sync + 'a>,
            Parser::Esedb(parser) => Box::new(
                parser
                    .parse()
                    .map(|r| {
                        r.and_then(|v| {
                            serde_json::to_value(v)
                                .with_context(|| "unexpected JSON serialization error")
                        })
                    })
                    .map(|r| r.map(Document::Esedb)),
            )
                as Box<dyn Iterator<Item = crate::Result<Document>> + Send + Sync + 'a>,
            Parser::Unknown => Box::new(Unknown)
                as Box<dyn Iterator<Item = crate::Result<Document>> + Send + Sync + 'a>,
        };
        Documents { iterator }
    }

    pub fn kind(&self) -> Kind {
        match self.parser {
            Parser::Evtx(_) => Kind::Evtx,
            Parser::Hve(_) => Kind::Hve,
            Parser::Json(_) => Kind::Json,
            Parser::Jsonl(_) => Kind::Jsonl,
            Parser::Mft(_) => Kind::Mft,
            Parser::Xml(_) => Kind::Xml,
            Parser::Esedb(_) => Kind::Esedb,
            Parser::Unknown => Kind::Unknown,
        }
    }
}

pub fn get_files(
    path: &PathBuf,
    extensions: &Option<HashSet<String>>,
    skip_errors: bool,
) -> crate::Result<Vec<PathBuf>> {
    let mut files: Vec<PathBuf> = vec![];
    if path.exists() {
        let metadata = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(e) => {
                if skip_errors {
                    cs_eyellowln!("[!] failed to get metadata for file - {}", e);
                    return Ok(files);
                } else {
                    anyhow::bail!(e);
                }
            }
        };
        if metadata.is_dir() {
            let directory = match path.read_dir() {
                Ok(directory) => directory,
                Err(e) => {
                    if skip_errors {
                        cs_eyellowln!("[!] failed to read directory - {}", e);
                        return Ok(files);
                    } else {
                        anyhow::bail!(e);
                    }
                }
            };
            for dir in directory {
                let dir = match dir {
                    Ok(dir) => dir,
                    Err(e) => {
                        if skip_errors {
                            cs_eyellowln!("[!] failed to enter directory - {}", e);
                            return Ok(files);
                        } else {
                            anyhow::bail!(e);
                        }
                    }
                };
                files.extend(get_files(&dir.path(), extensions, skip_errors)?);
            }
        } else if let Some(e) = extensions {
            if let Some(ext) = path.extension() {
                if e.contains(&ext.to_string_lossy().into_owned()) {
                    files.push(path.to_path_buf());
                }
            }
            // Edge cases
            if e.contains("$MFT") && path.file_name().and_then(|e| e.to_str()) == Some("$MFT") {
                files.push(path.to_path_buf());
            }
        } else {
            files.push(path.to_path_buf());
        }
    } else if skip_errors {
        cs_eyellowln!("[!] Specified path does not exist - {}", path.display());
    } else {
        anyhow::bail!("Specified event log path is invalid - {}", path.display());
    }
    Ok(files)
}

pub fn win32_ts_to_datetime(ts_win32: u64) -> crate::Result<DateTime<Utc>> {
    let ts_unix = (ts_win32 / 10_000) as i64 - 11644473600000;
    DateTime::from_timestamp_millis(ts_unix).ok_or(anyhow!("Timestamp out of range!"))
}
