use crate::hunt::{get_mapping_file, load_detection_rules, RuleType};
use anyhow::Result;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt)]
pub struct CheckOpts {
    /// Specify a directory containing detection rules to use. All files matching *.yml will be used.
    rules_path: PathBuf,

    /// Specify the mapping file to use to with the specified detection rules.
    /// Required when using the --rule/-r flag
    #[structopt(short = "m", long = "mapping")]
    pub mapping_path: PathBuf,

    /// Print verbose
    #[structopt(short = "v", long = "verbose")]
    pub verbose: bool,
}

pub fn run_check(opt: CheckOpts) -> Result<String> {
    let mapping_file = get_mapping_file(&opt.mapping_path)?;
    match RuleType::from(&mapping_file.kind) {
        Some(RuleType::Sigma) => {}
        Some(RuleType::Stalker) => {}
        None => {
            return Err(anyhow!(
                "Unsupported rule kind: {} - supported values are 'sigma' or 'stalker'",
                mapping_file.kind
            ))
        }
    }
    cs_println!("[+] Validating supplied detection rules...\n\r");
    load_detection_rules(&opt.rules_path, true, &mapping_file, opt.verbose)?;
    Ok("".to_string())
}
