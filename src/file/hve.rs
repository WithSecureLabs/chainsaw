use std::path::Path;

use notatin::{
    err::Error as HveError,
    parser_builder::{ParserBuilder},
    parser::{ParserIterator, Parser as HveParser}, cell_key_node::CellKeyNode,
};
use regex::RegexSet;

use crate::search::Searchable;

pub type Hve = CellKeyNode;


pub struct Parser {
    pub inner: HveParser,
}

impl Parser {
    pub fn load(file: &Path) -> crate::Result<Self> {
        let path = match file.to_str() {
            Some(path) => path,
            None => panic!("Could not convert path to string!"),
        };
        let parser: HveParser = ParserBuilder::from_path(String::from(path))
            .recover_deleted(false)
            // .with_transaction_log(log1_path)
            // .with_transaction_log(log2_path)
            .build()?;
        
        Ok(Self {inner: parser})
    }
    
    pub fn parse(&mut self) -> impl Iterator<Item = Result<CellKeyNode, anyhow::Error>> + '_ {
        ParserIterator::new(&self.inner).iter().map(Ok)
    }
}

impl Searchable for CellKeyNode {
    fn matches(&self, regex: &RegexSet) -> bool {
        for value in self.value_iter() {
            if regex.is_match(&value.get_content().0.to_string()) {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const CACHE_PATH: &str = "/mnt/hgfs/vm_shared/challenge1/cache/shim/";

    #[test]
    fn hve_lib_works() -> Result<(), HveError> {
        let system_path = [CACHE_PATH, "SYSTEM"].join("");
        let log1_path = [CACHE_PATH, "SYSTEM.LOG1"].join("");
        let log2_path = [CACHE_PATH, "SYSTEM.LOG2"].join("");

        let parser: HveParser = ParserBuilder::from_path(system_path)
            .recover_deleted(false)
            .with_transaction_log(log1_path)
            .with_transaction_log(log2_path)
            .build()?;
        
            
        for key in ParserIterator::new(&parser).iter() {
            println!("{}", key.path);
            for value in key.value_iter() {
                println!("\t{} {:?}", value.get_pretty_name(), value.get_content());
            }
        }
        Ok(())
    }
}