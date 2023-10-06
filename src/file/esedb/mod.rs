use std::collections::HashMap;
use std::{fs, path::Path};

use anyhow::Error;
use chrono::{DateTime, SecondsFormat, Utc};
use libesedb::EseDb;
use libesedb::Value as EseValue;
use serde_json::json;
use serde_json::Value as Json;

pub mod srum;

pub type Esedb = Json;

pub struct Parser {
    pub database: EseDb,
    pub esedb_entries: Vec<HashMap<String, Json>>,
}

impl Parser {
    // Implement a generic ESE database parser using libesedb

    pub fn load(file_path: &Path) -> crate::Result<Self> {
        // Load the ESE database
        let ese_db = EseDb::open(file_path)?;
        cs_eprintln!(
            "[+] ESE database file loaded from {:?}",
            fs::canonicalize(file_path).expect("could not get the absolute path")
        );
        Ok(Self {
            database: ese_db,
            esedb_entries: Vec::new(),
        })
    }

    pub fn parse(
        &mut self,
    ) -> impl Iterator<Item = crate::Result<HashMap<String, Json>, Error>> + 'static {
        cs_eprintln!("[+] Parsing the ESE database...");

        let iter_tables = self
            .database
            .iter_tables()
            .expect("unable to iterate over the tables in the ESE database");

        // Iterate through the database tables
        for table in iter_tables.flatten() {
            let table_name = table
                .name()
                .expect("unable to get table name from the ESE database");
            let mut column_names = Vec::new();

            let iter_table_columns = table
                .iter_columns()
                .expect("unable to iterate over the columns in the ESE database table");

            // Retrieve the column names
            for column in iter_table_columns.flatten() {
                let name = column
                    .name()
                    .expect("unable to get column name from the ESE database table {}");
                column_names.push(name);
            }

            let iter_table_records = table
                .iter_records()
                .expect("unable to iterate over the records in the ESE database table");

            // Iterate through the database records
            for rec in iter_table_records.flatten() {
                let mut row_hashmap = HashMap::new();
                row_hashmap.insert("Table".to_string(), Json::String(table_name.clone()));

                let iter_record_values = rec
                    .iter_values()
                    .expect("unable to iterate over the records in the ESE database table");

                // Iterate through the values in database records
                for (ese_val, column_name) in iter_record_values.zip(&column_names) {
                    let ese_val = match ese_val {
                        Ok(v) => v,
                        Err(_) => EseValue::Null(()),
                    };

                    match ese_val {
                        EseValue::DateTime(_) => {
                            let st = ese_val
                                .to_oletime()
                                .expect("unable to convert a DateTime value into a OleTime value");
                            let datetime: DateTime<Utc> = DateTime::from(st);
                            let datetime_format =
                                datetime.to_rfc3339_opts(SecondsFormat::Secs, true);
                            row_hashmap.insert(column_name.clone(), Json::String(datetime_format));
                        }
                        EseValue::I64(v) | EseValue::Currency(v) => {
                            row_hashmap.insert(column_name.clone(), json!(v));
                        }
                        EseValue::U8(v) => {
                            row_hashmap.insert(column_name.clone(), json!(v));
                        }
                        EseValue::I16(v) => {
                            row_hashmap.insert(column_name.clone(), json!(v));
                        }
                        EseValue::I32(v) => {
                            row_hashmap.insert(column_name.clone(), json!(v));
                        }
                        EseValue::F32(v) => {
                            row_hashmap.insert(column_name.clone(), json!(v));
                        }
                        EseValue::F64(v) => {
                            row_hashmap.insert(column_name.clone(), json!(v));
                        }
                        EseValue::Binary(v)
                        | EseValue::LargeBinary(v)
                        | EseValue::SuperLarge(v)
                        | EseValue::Guid(v) => {
                            row_hashmap.insert(
                                column_name.clone(),
                                serde_json::to_value(v).unwrap_or_default(),
                            );
                        }
                        EseValue::Text(v) | EseValue::LargeText(v) => {
                            row_hashmap.insert(column_name.clone(), Json::String(v));
                        }
                        EseValue::U32(v) => {
                            row_hashmap.insert(column_name.clone(), json!(v));
                        }
                        EseValue::U16(v) => {
                            row_hashmap.insert(column_name.clone(), json!(v));
                        }
                        EseValue::Null(_) => {
                            row_hashmap.insert(column_name.clone(), Json::Null);
                        }
                        _ => {
                            row_hashmap
                                .insert(column_name.clone(), Json::String(ese_val.to_string()));
                        }
                    };
                }
                self.esedb_entries.push(row_hashmap);
            }
        }

        self.esedb_entries.clone().into_iter().map(Ok)
    }
}
