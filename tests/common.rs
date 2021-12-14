use std::fs;
use std::path::Path;

use anyhow::Error;

pub fn load_file(prefix: &str, name: &str) -> Result<String, Error> {
    let root = env!("CARGO_MANIFEST_DIR");
    let path = Path::new(root).join(prefix).join(name);
    let contents = fs::read_to_string(path).expect("failed to read rule");
    Ok(contents)
}
