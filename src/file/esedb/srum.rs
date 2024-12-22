use std::collections::HashMap;

use anyhow::Context;

#[derive(Debug)]
pub struct SruDbIdMapTableEntry {
    pub id_type: i8,
    pub id_index: i32,
    pub id_blob: Option<Vec<u8>>,
    pub id_blob_as_string: Option<String>,
}

impl super::Parser {
    // Parse SruDbIdMapTable table from SRUM database
    pub fn parse_sru_db_id_map_table(
        &self,
    ) -> crate::Result<HashMap<String, SruDbIdMapTableEntry>> {
        // Filter the entries where "Table" is "SruDbIdMapTable"
        let table_entries = self.esedb_entries.iter().filter(|entry| {
            entry
                .get("Table")
                .and_then(|v| v.as_str())
                .is_some_and(|name| name == "SruDbIdMapTable")
        });

        let mut mapped_table_entries = HashMap::new();

        for table_entry in table_entries {
            let idblob_value: Option<Vec<u8>> = if let Some(id_blob) = table_entry.get("IdBlob") {
                if id_blob.is_null() {
                    None
                } else {
                    Some(
                        serde_json::from_value(id_blob.clone())
                            .with_context(|| "unable to get IdBlob from SruDbIdMapTable")?,
                    )
                }
            } else {
                None
            };

            let mut sru_db_id_map_table_entry = SruDbIdMapTableEntry {
                id_type: serde_json::from_value(table_entry["IdType"].clone())
                    .with_context(|| "unable to get IdType from SruDbIdMapTable")?,
                id_index: serde_json::from_value(table_entry["IdIndex"].clone())
                    .with_context(|| "unable to get IdIndex from SruDbIdMapTable")?,
                id_blob: idblob_value,
                id_blob_as_string: None,
            };

            // Not a Windows SID
            if sru_db_id_map_table_entry.id_type != 3 {
                if let Some(id_blob) = &sru_db_id_map_table_entry.id_blob {
                    // Convert the Vec<u8> to a string
                    // Using from_utf8_lossy() instead of from_utf8() to prevent decoding errors (e.g., Chinese characters)
                    let s = String::from_utf8_lossy(&id_blob.to_vec()).replace('\u{0000}', "");
                    sru_db_id_map_table_entry.id_blob_as_string = Some(s);
                }
            }

            mapped_table_entries.insert(
                sru_db_id_map_table_entry.id_index.to_string(),
                sru_db_id_map_table_entry,
            );
        }
        Ok(mapped_table_entries)
    }
}
