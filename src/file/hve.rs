use std::path::Path;
use notatin::{
    parser_builder::{ParserBuilder},
    parser::{ParserIterator, Parser as HveParser},
};
use anyhow::Error;
use serde_json::Value as Json;

pub type Hve = Json;


pub struct Parser {
    pub inner: HveParser,
}

impl Parser {
    pub fn load(file: &Path) -> crate::Result<Self> {
        let path = match file.to_str() {
            Some(path) => path,
            None => anyhow::bail!("Could not convert path to string!"),
        };
        let parser: HveParser = ParserBuilder::from_path(String::from(path))
            .recover_deleted(false)
            .build()?;
        
        Ok(Self {inner: parser})
    }
    
    pub fn parse(&mut self) -> impl Iterator<Item = Result<Json, Error>> + '_ {
        ParserIterator::new(&self.inner).iter().map(|c| match serde_json::to_value(c) {
            Ok(json) => Ok(json),
            Err(e) => anyhow::bail!(e),
        })
    }
}
