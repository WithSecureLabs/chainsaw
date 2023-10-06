use std::{
    fs,
    path::{Path, PathBuf},
};

use notatin::{
    parser::{Parser as HveParser, ParserIterator},
    parser_builder::ParserBuilder,
};
use serde_json::Value as Json;

pub mod amcache;
pub mod shimcache;
pub mod srum;

pub type Hve = Json;

pub struct Parser {
    pub inner: HveParser,
}

impl Parser {
    pub fn load(path: &Path) -> crate::Result<Self> {
        // Find registry transaction logs from the same directory
        let mut transaction_log_files: Vec<PathBuf> = Vec::new();
        let parent_dir = path
            .parent()
            .ok_or(anyhow!("Could not get registry hive parent directory!"))?;
        let hive_file_name = path.file_name();
        let parent_dir_files = fs::read_dir(parent_dir)?.collect::<Result<Vec<_>, _>>()?;
        for dir_entry in parent_dir_files {
            let path = dir_entry.path();
            if path.file_stem() == hive_file_name {
                let file_extension = path.extension();
                if let Some(extension) = file_extension {
                    if extension == "LOG" || extension == "LOG1" || extension == "LOG2" {
                        transaction_log_files.push(path);
                    }
                }
            }
        }

        // Build parser
        let mut parser_builder = ParserBuilder::from_path(PathBuf::from(path));

        if transaction_log_files.is_empty() {
            parser_builder.recover_deleted(false);
        } else {
            parser_builder.recover_deleted(true);
            cs_eprintln!(
                "[+] Loading the hive {:?} with the transaction logs...",
                fs::canonicalize(path).expect("could not get the absolute path")
            );
            for log_file in transaction_log_files {
                parser_builder.with_transaction_log(log_file);
            }
        }

        let parser = match parser_builder.build() {
            Ok(parser) => parser,
            Err(error) => {
                cs_eyellowln!(
                    "[!] Failed to load hive {:?} with deleted record recovery. Error: \"{}\".\n    Reattempting without recovery...",
                    path,
                    error
                );
                parser_builder.recover_deleted(false);
                parser_builder.build()?
            }
        };

        Ok(Self { inner: parser })
    }

    pub fn parse(&mut self) -> impl Iterator<Item = crate::Result<Json>> + '_ {
        ParserIterator::new(&self.inner)
            .iter()
            .map(|c| match serde_json::to_value(c) {
                Ok(json) => Ok(json),
                Err(e) => bail!(e),
            })
    }
}
