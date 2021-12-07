use std::fs;
use std::path::Path;

use anyhow::Error;

pub fn load_file(prefix: &str, name: &str) -> Result<String, Error> {
    let rule = if name.ends_with(".yml") {
        name.to_owned()
    } else {
        format!("{}.yml", name)
    };
    let root = env!("CARGO_MANIFEST_DIR");
    let path = Path::new(root).join(prefix).join(rule);
    let contents = fs::read_to_string(path).expect("failed to read rule");
    Ok(contents)
}
