use std::path::Path;
use std::{fs::File, io::BufReader};

use mft::csv::FlatMftEntryWithName;
use mft::{MftEntry, MftParser};
use serde_json::Value as Json;
use tau_engine::{Document, Value as Tau};

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
        // Really don't love this but I'm limited by parsing lib
        let entries: Vec<Result<MftEntry, mft::err::Error>> = self.inner.iter_entries().collect();
        let mut flat: Vec<crate::Result<FlatMftEntryWithName>> = vec![];
        for entry in entries {
            flat.push(match entry {
                Ok(e) => Ok(mft::csv::FlatMftEntryWithName::from_entry(
                    &e,
                    &mut self.inner,
                )),
                Err(err) => Err(anyhow!(err)),
            });
        }
        let mut json = vec![];
        for entry in flat {
            json.push(match entry {
                Ok(e) => match serde_json::to_value(e) {
                    Ok(j) => Ok(j),
                    Err(err) => Err(anyhow!(err)),
                },
                Err(err) => Err(anyhow!(err)),
            });
        }
        json.into_iter()
    }
}
