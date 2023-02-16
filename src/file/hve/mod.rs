use std::{path::{PathBuf, Path}, fs};

use anyhow::{Result, bail};
use notatin::{
    parser::{Parser as HveParser, ParserIterator},
    parser_builder::ParserBuilder,
};
use serde_json::Value as Json;

pub mod shimcache;
pub mod amcache;

pub type Hve = Json;

pub struct Parser {
    pub inner: HveParser,
}

impl Parser {
    pub fn load(path: &Path) -> crate::Result<Self> {
        // Find registry transaction logs from the same directory
        let mut transaction_log_files: Vec<PathBuf> = Vec::new();
        let parent_dir = path.parent().ok_or(anyhow!("Could not get registry hive parent directory!"))?;
        let hive_file_name = path.file_name();
        let parent_dir_files = fs::read_dir(parent_dir)?.into_iter().collect::<Result<Vec<_>,_>>()?;
        for dir_entry in parent_dir_files {
            let path = dir_entry.path();
            if path.file_stem() == hive_file_name {
                let file_extension = path.extension();
                if let Some(extension) = file_extension {
                    if extension == "LOG"
                    || extension == "LOG1"
                    || extension == "LOG2" {
                        transaction_log_files.push(path);
                    }
                }
            }
        }

        // Build parser
        let mut parser_builder = ParserBuilder::from_path(PathBuf::from(path));
        parser_builder.recover_deleted(true);
        for log_file in transaction_log_files {
            parser_builder.with_transaction_log(log_file);
        }

        let parser = parser_builder.build()?;

        Ok(Self { inner: parser })
    }

    pub fn parse(&mut self) -> impl Iterator<Item = Result<Json>> + '_ {
        ParserIterator::new(&self.inner)
            .iter()
            .map(|c| match serde_json::to_value(c) {
                Ok(json) => Ok(json),
                Err(e) => bail!(e),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amcache_parsing_works_win10() -> Result<()> {
        let mut parser = Parser::load(&PathBuf::from(
            "/mnt/hgfs/vm_shared/win10_vm_hives/am/Amcache.hve",
        ))?;
        let artifact_map = parser.parse_amcache()?;
        println!("{:#?}", artifact_map);
        Ok(())
    }

    #[test]
    fn shimcache_parsing_works_win7() -> Result<()> {
        let mut parser = Parser::load(&PathBuf::from(
            "/mnt/hgfs/vm_shared/Module 5 - Disk/cache/shimcache/SYSTEM",
        ))?;
        let _shimcache_entries = parser.parse_shimcache()?;
        Ok(())
    }

    #[test]
    fn shimcache_parsing_works_win10() -> Result<()> {
        let mut parser = Parser::load(&PathBuf::from(
            "/mnt/hgfs/vm_shared/win10_vm_hives/shim/SYSTEM",
        ))?;
        let shimcache= parser.parse_shimcache()?;
        for entry in shimcache.entries {
            println!("{entry}");
        }
        Ok(())
    }

}
