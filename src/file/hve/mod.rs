use std::{path::{PathBuf, Path}};

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
        let parser: HveParser = ParserBuilder::from_path(PathBuf::from(path))
            .recover_deleted(false)
            .build()?;

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
        let shimcache_entries = parser.parse_shimcache()?;
        for entry in shimcache_entries {
            println!("{entry}");
        }
        Ok(())
    }

}
