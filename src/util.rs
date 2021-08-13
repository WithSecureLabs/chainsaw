use std::fs;
use std::fs::{metadata, File, OpenOptions};
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Result;
use evtx::{EvtxParser, ParserSettings};
use indicatif::{ProgressBar, ProgressStyle};
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
		println!("[+] Found {} EVTX files", evtx_files.len());
	} else {
		return Err(anyhow!("No EVTx files found. Check input path?"));
	}
	Ok(evtx_files)
}

pub fn parse_evtx_file(evtx_file: &Path) -> Result<evtx::EvtxParser<File>> {
	let settings = ParserSettings::default().num_threads(0);
	let parser = EvtxParser::from_path(evtx_file)?.with_configuration(settings);
	Ok(parser)
}

pub fn json_write_to_file(out_file: &Path, records: &serde_json::value::Value) -> Result<()> {
	let mut ofile = match OpenOptions::new().write(true).append(true).open(out_file) {
		Ok(file) => file,
		Err(_) => File::create(out_file)?,
	};

	match serde_json::to_string_pretty(&records) {
		Ok(g) => {
			ofile.write_all(g.as_bytes())?;
			ofile.write_all("\n".as_bytes())?;
		}
		Err(e) => return Err(anyhow!("{}", e)),
	}
	Ok(())
}

pub fn check_output_file(file: &Path) -> Result<()> {
	// We want to sanity check the specified output file before we do heavy processing
	if file.exists() {
		print!("Output file already exists, Overwrite? [y]es/[n]o: ");
		io::stdout().flush()?;
		let mut input = String::new();
		io::stdin()
			.read_line(&mut input)
			.expect("Failed to read from stdin!");
		if input.ends_with('\n') {
			input.pop();
		}
		match input.as_str() {
			"Yes" => {}
			"yes" => {}
			"y" => {}
			"Y" => {}
			_ => return Err(anyhow!("Exiting")),
		}
	}
	Ok(())
}

pub fn get_progress_bar(size: u64, msg: String) -> indicatif::ProgressBar {
	let pb = ProgressBar::new(size);
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
