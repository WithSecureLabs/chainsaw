use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use self::evtx::{Evtx, Parser as EvtxParser};
use self::json::{Json, Parser as JsonParser};

pub mod evtx;
pub mod json;

#[derive(Clone)]
pub enum Document {
    Evtx(Evtx),
    Json(Json),
}

pub struct Documents<'a> {
    iterator: Box<dyn Iterator<Item = crate::Result<Document>> + 'a>,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Evtx,
    Json,
    Unknown,
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
    Json(JsonParser),
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
                "evtx" => Ok(Self {
                    parser: Parser::Evtx(EvtxParser::load(file)?),
                }),
                "json" => Ok(Self {
                    parser: Parser::Json(JsonParser::load(file)?),
                }),
                _ => {
                    if load_unknown {
                        if skip_errors {
                            cs_eyellowln!("file type is not currently supported - {}", extension);
                            Ok(Self {
                                parser: Parser::Unknown,
                            })
                        } else {
                            anyhow::bail!("file type is not currently supported - {}", extension)
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
                    } else if let Ok(parser) = JsonParser::load(file) {
                        return Ok(Self {
                            parser: Parser::Json(parser),
                        });
                    }
                    if skip_errors {
                        cs_eyellowln!("file type is not known");

                        Ok(Self {
                            parser: Parser::Unknown,
                        })
                    } else {
                        anyhow::bail!("file type is not known")
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
                    .map(|r| r.map(|d| Document::Evtx(d)).map_err(|e| e.into())),
            )
                as Box<dyn Iterator<Item = crate::Result<Document>> + 'a>,
            Parser::Json(parser) => Box::new(parser.parse().map(|r| r.map(|d| Document::Json(d))))
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
            Parser::Json(_) => Kind::Json,
            Parser::Unknown => Kind::Unknown,
        }
    }
}

pub fn get_files(
    path: &PathBuf,
    extension: &Option<String>,
    skip_errors: bool,
) -> crate::Result<Vec<PathBuf>> {
    let mut files: Vec<PathBuf> = vec![];
    if path.exists() {
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(e) => {
                if skip_errors {
                    cs_eyellowln!("failed to get metadata for file - {}", e);
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
                        cs_eyellowln!("failed to read directory - {}", e);
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
                            cs_eyellowln!("failed to enter directory - {}", e);
                            return Ok(files);
                        } else {
                            anyhow::bail!(e);
                        }
                    }
                };
                files.extend(get_files(&dir.path(), &extension, skip_errors)?);
            }
        } else {
            if let Some(extension) = extension {
                if let Some(ext) = path.extension() {
                    if ext == extension.as_str() {
                        files.push(path.to_path_buf());
                    }
                }
            } else {
                files.push(path.to_path_buf());
            }
        }
    } else {
        anyhow::bail!("Invalid input path: {}", path.display());
    }
    Ok(files)
}
