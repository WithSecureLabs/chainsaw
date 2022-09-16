use std::path::Path;
use std::{fs::File, io::BufReader};

use mft::csv::FlatMftEntryWithName;
use mft::MftParser;
use serde_json::Value as Json;

pub type Mft = Json;

pub struct Parser {
    pub inner: MftParser<BufReader<File>>,
}

impl Parser {
    pub fn load(file: &Path) -> crate::Result<Self> {
        let parser = MftParser::from_path(file)?;
        Ok(Self { inner: parser })
    }

    pub fn parse(&mut self) -> impl Iterator<Item = crate::Result<Json>> + '_ {
        // FIXME: Due to the nested borrowing we still have to do a full pass which is memory
        // hungry but there is no easy way around this for now...
        let entries = self.inner.iter_entries().collect::<Vec<_>>();
        entries.into_iter().map(|e| match e {
            Ok(e) => serde_json::to_value(FlatMftEntryWithName::from_entry(&e, &mut self.inner))
                .map_err(|e| e.into()),
            Err(e) => anyhow::bail!(e),
        })
    }
}
