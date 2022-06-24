use std::fs;
use std::fs::{metadata, File};
use std::path::{Path, PathBuf};

use anyhow::Result;
use evtx::{EvtxParser, ParserSettings};
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
#[cfg(windows)]
use is_elevated::is_elevated as user_is_elevated;
use walkdir::WalkDir;

#[cfg(not(windows))]
pub const RULE_PREFIX: &str = "‣ ";

#[cfg(windows)]
pub const RULE_PREFIX: &str = "+ ";

#[cfg(not(windows))]
const TICK_SETTINGS: (&str, u64) = ("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏ ", 80);

#[cfg(windows)]
const TICK_SETTINGS: (&str, u64) = (r"-\|/-", 200);

pub fn large_event_logs(files: &[PathBuf]) -> bool {
    for file in files {
        let metadata = match fs::metadata(file) {
            Ok(a) => a,
            Err(_) => return false,
        };
        if metadata.len() > 500000000 {
            return true;
        }
    }
    false
}

pub fn get_evtx_files(mut path: &Path) -> Result<Vec<PathBuf>> {
    let mut evtx_files: Vec<PathBuf> = Vec::new();
    if path.display().to_string() == *"win_default" {
        #[cfg(windows)]
        if !user_is_elevated() {
            return Err(anyhow!(
                "Cannot access local event logs - you are not running in an elevated session!"
            ));
        }
        path = Path::new("C:\\Windows\\System32\\winevt\\Logs\\");
    };
    if path.exists() {
        let md = metadata(&path)?;
        if md.is_dir() {
            // Grab files from within the specified directory
            // Check that the file ends in evtx
            for file in WalkDir::new(path) {
                let file_a = file?;
                if let Some(x) = file_a.path().extension() {
                    if x == "evtx" {
                        evtx_files.push(file_a.into_path());
                    }
                }
            }
        } else {
            evtx_files = vec![path.to_path_buf()];
        }
    } else {
        return Err(anyhow!("Invalid input path: {}", path.display()));
    };
    // Check if there is at least one EVTX file in the directory
    if !evtx_files.is_empty() {
        cs_eprintln!("[+] Found {} EVTX files", evtx_files.len());
    } else {
        return Err(anyhow!("No EVTx files found. Check input path?"));
    }
    Ok(evtx_files)
}

pub fn parse_evtx_file(evtx_file: &Path) -> Result<evtx::EvtxParser<File>> {
    let settings = ParserSettings::default()
        .separate_json_attributes(true)
        .num_threads(0);
    let parser = EvtxParser::from_path(evtx_file)?.with_configuration(settings);
    Ok(parser)
}

pub fn get_progress_bar(size: u64, msg: String) -> indicatif::ProgressBar {
    let pb = ProgressBar::new(size);
    
        match unsafe {crate::write::WRITER.quiet} {
            true => pb.set_draw_target(ProgressDrawTarget::hidden()),
            false => pb.set_draw_target(ProgressDrawTarget::stderr()),
        }
   
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[+] {msg}: [{bar:40}] {pos}/{len} {spinner}")
            .tick_chars(TICK_SETTINGS.0)
            .progress_chars("=>-"),
    );

    pb.set_message(msg);
    pb.enable_steady_tick(TICK_SETTINGS.1);
    pb
}
