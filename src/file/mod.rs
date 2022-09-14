use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use self::evtx::{Evtx, Parser as EvtxParser};
use self::json::{lines::Parser as JsonlParser, Json, Parser as JsonParser};
use self::mft::{Mft, Parser as MftParser};
use self::xml::{Parser as XmlParser, Xml};

pub mod evtx;
pub mod json;
pub mod mft;
pub mod xml;

#[derive(Clone)]
pub enum Document {
    Evtx(Evtx),
    Mft(Mft),
    Json(Json),
    Xml(Xml),
}

pub struct Documents<'a> {
    iterator: Box<dyn Iterator<Item = crate::Result<Document>> + 'a>,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize, Hash, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Evtx,
    Mft,
    Json,
    Jsonl,
    Xml,
    Unknown,
}

impl Kind {
    pub fn extensions(&self) -> Option<Vec<String>> {
        match self {
            Kind::Evtx => Some(vec!["evtx".to_string()]),
            Kind::Mft => Some(vec!["mft".to_string(), "bin".to_string()]),
            Kind::Json => Some(vec!["json".to_string()]),
            Kind::Jsonl => Some(vec!["jsonl".to_string()]),
            Kind::Xml => Some(vec!["xml".to_string()]),
            Kind::Unknown => None,
        }
    }
}

impl<'a> Iterator for Documents<'a> {
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

pub enum Parser {
    Evtx(EvtxParser),
    Mft(MftParser),
    Json(JsonParser),
    Jsonl(JsonlParser),
    Xml(XmlParser),
    Unknown,
}

pub struct Reader {
    parser: Parser,
}

impl Reader {
    pub fn load(file: &Path, load_unknown: bool, skip_errors: bool) -> crate::Result<Self> {
        // NOTE: We don't want to use libmagic because then we have to include databases etc... So
        // for now we assume that the file extensions are correct!
        match file.extension().and_then(|e| e.to_str()) {
            Some(extension) => match extension {
                "evtx" => {
                    let parser = match EvtxParser::load(file) {
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
                "mft" => {
                    let parser = match MftParser::load(file) {
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
                "json" => {
                    let parser = match JsonParser::load(file) {
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
                    let parser = match JsonlParser::load(file) {
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
                "xml" => {
                    let parser = match XmlParser::load(file) {
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
                _ => {
                    if load_unknown {
                        if let Ok(parser) = EvtxParser::load(file) {
                            return Ok(Self {
                                parser: Parser::Evtx(parser),
                            });
                        } else if let Ok(parser) = MftParser::load(file) {
                            return Ok(Self {
                                parser: Parser::Mft(parser),
                            });
                        } else if let Ok(parser) = JsonParser::load(file) {
                            return Ok(Self {
                                parser: Parser::Json(parser),
                            });
                        } else if let Ok(parser) = XmlParser::load(file) {
                            return Ok(Self {
                                parser: Parser::Xml(parser),
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
                if load_unknown {
                    if let Ok(parser) = EvtxParser::load(file) {
                        return Ok(Self {
                            parser: Parser::Evtx(parser),
                        });
                    } else if let Ok(parser) = MftParser::load(file) {
                        return Ok(Self {
                            parser: Parser::Mft(parser),
                        });
                    } else if let Ok(parser) = JsonParser::load(file) {
                        return Ok(Self {
                            parser: Parser::Json(parser),
                        });
                    } else if let Ok(parser) = XmlParser::load(file) {
                        return Ok(Self {
                            parser: Parser::Xml(parser),
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
                as Box<dyn Iterator<Item = crate::Result<Document>> + 'a>,
            Parser::Mft(parser) => Box::new(parser.parse().map(|r| r.map(Document::Mft)))
                as Box<dyn Iterator<Item = crate::Result<Document>> + 'a>,
            Parser::Json(parser) => Box::new(parser.parse().map(|r| r.map(Document::Json)))
                as Box<dyn Iterator<Item = crate::Result<Document>> + 'a>,
            Parser::Jsonl(parser) => Box::new(parser.parse().map(|r| r.map(Document::Json)))
                as Box<dyn Iterator<Item = crate::Result<Document>> + 'a>,
            Parser::Xml(parser) => Box::new(parser.parse().map(|r| r.map(Document::Xml)))
                as Box<dyn Iterator<Item = crate::Result<Document>> + 'a>,
            Parser::Unknown => {
                Box::new(Unknown) as Box<dyn Iterator<Item = crate::Result<Document>> + 'a>
            }
        };
        Documents { iterator }
    }

    pub fn kind(&self) -> Kind {
        match self.parser {
            Parser::Evtx(_) => Kind::Evtx,
            Parser::Mft(_) => Kind::Mft,
            Parser::Json(_) => Kind::Json,
            Parser::Jsonl(_) => Kind::Jsonl,
            Parser::Xml(_) => Kind::Xml,
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
        let metadata = match fs::metadata(&path) {
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
