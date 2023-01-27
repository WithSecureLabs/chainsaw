use anyhow::Error;
use chrono::NaiveDateTime;
use notatin::{
    cell_key_node::CellKeyNode,
    parser::{Parser as HveParser, ParserIterator},
    parser_builder::ParserBuilder,
};
use serde_json::Value as Json;
use std::path::Path;

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

        Ok(Self { inner: parser })
    }

    pub fn parse(&mut self) -> impl Iterator<Item = Result<Json, Error>> + '_ {
        ParserIterator::new(&self.inner)
            .iter()
            .map(|c| match serde_json::to_value(c) {
                Ok(json) => Ok(json),
                Err(e) => anyhow::bail!(e),
            })
    }

    pub fn parse_amcache(&mut self) -> Result<CellKeyNode, Error> {
        fn string_value_from_key(key: &CellKeyNode, value_name: &str) -> Result<String, Error> {
            let Some(key_value) = key.get_value(value_name) else {
                return Err(anyhow::anyhow!(
                    "Could not extract value \"{}\" from key \"{}\"",
                    value_name, key.get_pretty_path()
                ));
            };
            Ok(key_value.get_content().0.to_string())
        }

        // Parse registry key InventoryApplicationFile
        let key_inventory_application_file = self
            .inner
            .get_key("Root\\InventoryApplicationFile", false)?;
        let Some(mut node_inventory_application_file) = key_inventory_application_file else {
            return Err(anyhow::anyhow!("Could not find InventoryApplicationFile key!"));
        };
        let subkeys = node_inventory_application_file
            .read_sub_keys(&mut self.inner);
        for key in subkeys {
            let program_id = string_value_from_key(&key, "ProgramId")?;
            let file_id = string_value_from_key(&key, "FileId")?;
            let path = string_value_from_key(&key, "LowerCaseLongPath")?;
            let link_date = string_value_from_key(&key, "LinkDate")?;

            let sha1_hash = &file_id[4..];

            let Some(last_modified_ts)
                = win32_ts_to_date_time(key.detail.last_key_written_date_and_time()) else {
                return Err(anyhow::anyhow!("Could not parse timestamp!"));
            };
            println!("{}", last_modified_ts);
            println!("{}", link_date);
            println!("{}", path);
            println!("{}\n", sha1_hash);
        }
        // Parse registry key InventoryApplication
        let key_inventory_application_file = self
            .inner
            .get_key("Root\\InventoryApplication", false)?;
        let Some(mut node_inventory_application) = key_inventory_application_file else {
            return Err(anyhow::anyhow!("Could not find InventoryApplication key!"));
        };
        let subkeys = node_inventory_application.read_sub_keys(&mut self.inner);
        for key in subkeys {
            let program_id = key.key_name.clone();
            let install_date = string_value_from_key(&key, "InstallDate")?;
        }

        //TODO: link executables using program id
        Ok(node_inventory_application)
    }
}

fn win32_ts_to_date_time(ts_win32: u64) -> Option<NaiveDateTime> {
    let ts_unix = ((ts_win32 / 10_000) - 11644473600000) as i64;
    chrono::prelude::NaiveDateTime::from_timestamp_millis(ts_unix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amcache_parsing_works() -> Result<(), Error> {
        let mut parser = Parser::load(&Path::new(
            "/mnt/hgfs/vm_shared/Module 5 - Disk/cache/amcache/Amcache.hve",
        ))?;
        let node = parser.parse_amcache()?;
        // println!("{:#?}", node);
        Ok(())
    }
}
