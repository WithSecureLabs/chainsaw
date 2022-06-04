#[macro_use]
extern crate chainsaw;

use std::fs::File;
use std::path::PathBuf;

use anyhow::Result;
use chrono::NaiveDateTime;
use chrono_tz::Tz;
use structopt::StructOpt;

use chainsaw::{
    cli, get_files, lint_rule, load_rule, set_writer, Format, Hunter, RuleKind, Searcher, Writer,
};

#[derive(StructOpt)]
#[structopt(
    name = "chainsaw",
    about = "Rapidly Search and Hunt through windows event logs"
)]
struct Opts {
    /// Hide Chainsaw's banner.
    #[structopt(long)]
    no_banner: bool,
    #[structopt(subcommand)]
    cmd: Command,
}

#[derive(StructOpt)]
enum Command {
    /// Hunt through event logs using detection rules and builtin logic.
    Hunt {
        /// The path to a collection of rules.
        rules: PathBuf,

        /// The paths to hunt through.
        path: Vec<PathBuf>,

        /// A mapping file to hunt with.
        #[structopt(short = "m", long = "mapping", number_of_values = 1)]
        mapping: Option<Vec<PathBuf>>,
        /// Additional rules to hunt with.
        #[structopt(short = "r", long = "rule", number_of_values = 1)]
        rule: Option<Vec<PathBuf>>,

        /// Set the column width for the tabular output.
        #[structopt(long = "column-width", conflicts_with = "json")]
        column_width: Option<u32>,
        /// Print the output in csv format.
        #[structopt(group = "format", long = "csv", requires("output"))]
        csv: bool,
        /// Only hunt through files with the provided extension.
        #[structopt(long = "extension")]
        extension: Option<String>,
        /// The timestamp to hunt from. Drops any documents older than the value provided.
        #[structopt(long = "from")]
        from: Option<NaiveDateTime>,
        /// Print the full values for the tabular output.
        #[structopt(long = "full", conflicts_with = "json")]
        full: bool,
        /// Print the output in json format.
        #[structopt(group = "format", long = "json")]
        json: bool,
        /// Allow chainsaw to try and load files it cannot identify.
        #[structopt(long = "load-unknown")]
        load_unknown: bool,
        /// Output the timestamp using the local machine's timestamp.
        #[structopt(long = "local", group = "tz")]
        local: bool,
        /// Apply addional metadata for the tablar output.
        #[structopt(long = "metadata", conflicts_with = "json")]
        metadata: bool,
        /// The file/directory to output to.
        #[structopt(short = "o", long = "output")]
        output: Option<PathBuf>,
        /// Supress informational output.
        #[structopt(short = "q")]
        quiet: bool,
        /// Continue to hunt when an error is encountered.
        #[structopt(long = "skip-errors")]
        skip_errors: bool,
        /// Output the timestamp using the timezone provided.
        #[structopt(long = "timezone", group = "tz")]
        timezone: Option<Tz>,
        /// The timestamp to hunt up to. Drops any documents newer than the value provided.
        #[structopt(long = "to")]
        to: Option<NaiveDateTime>,
    },

    /// Lint provided rules to ensure that they load correctly
    Lint {
        /// The path to a collection of rules.
        path: PathBuf,
        /// The kind of rule to lint.
        #[structopt(long = "kind", default_value = "chainsaw")]
        kind: RuleKind,
    },

    /// Search through event logs for specific event IDs and/or keywords
    Search {
        /// A pattern to search for.
        #[structopt(required_unless_one=&["regexp", "tau"])]
        pattern: Option<String>,

        /// The paths to search through.
        path: Vec<PathBuf>,

        /// A pattern to search for.
        #[structopt(short = "e", long = "regexp", number_of_values = 1)]
        regexp: Option<Vec<String>>,

        /// Only search through files with the provided extension.
        #[structopt(long = "extension")]
        extension: Option<String>,
        /// The timestamp to search from. Drops any documents older than the value provided.
        #[structopt(long = "from")]
        from: Option<NaiveDateTime>,
        /// Ignore the case when searching patterns
        #[structopt(short = "i", long = "ignore-case")]
        ignore_case: bool,
        /// Print the output in json format.
        #[structopt(long = "json")]
        json: bool,
        /// Allow chainsaw to try and load files it cannot identify.
        #[structopt(long = "load-unknown")]
        load_unknown: bool,
        /// Output the timestamp using the local machine's timestamp.
        #[structopt(long = "local", group = "tz")]
        local: bool,
        /// The file to output to.
        #[structopt(short = "o", long = "output")]
        output: Option<PathBuf>,
        /// Supress informational output.
        #[structopt(short = "q")]
        quiet: bool,
        /// Continue to search when an error is encountered.
        #[structopt(long = "skip-errors")]
        skip_errors: bool,
        /// Tau expressions to search with.
        #[structopt(short = "t", long = "tau", number_of_values = 1)]
        tau: Option<Vec<String>>,
        /// The field that contains the timestamp.
        #[structopt(long = "timestamp", requires_if("from", "to"))]
        timestamp: Option<String>,
        /// Output the timestamp using the timezone provided.
        #[structopt(long = "timezone", group = "tz")]
        timezone: Option<Tz>,
        /// The timestamp to search up to. Drops any documents newer than the value provided.
        #[structopt(long = "to")]
        to: Option<NaiveDateTime>,
    },
}

fn print_title() {
    cs_eprintln!(
        "
 ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗███████╗ █████╗ ██╗    ██╗
██╔════╝██║  ██║██╔══██╗██║████╗  ██║██╔════╝██╔══██╗██║    ██║
██║     ███████║███████║██║██╔██╗ ██║███████╗███████║██║ █╗ ██║
██║     ██╔══██║██╔══██║██║██║╚██╗██║╚════██║██╔══██║██║███╗██║
╚██████╗██║  ██║██║  ██║██║██║ ╚████║███████║██║  ██║╚███╔███╔╝
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
    By F-Secure Countercept (@FranticTyping, @AlexKornitzer)
"
    );
}

fn init_writer(output: Option<PathBuf>, csv: bool, json: bool, quiet: bool) -> crate::Result<()> {
    let (path, output) = match &output {
        Some(path) => {
            if csv {
                (Some(path.to_path_buf()), None)
            } else {
                let file = match File::create(path) {
                    Ok(f) => f,
                    Err(e) => {
                        return Err(anyhow::anyhow!(
                            "Unable to write to specified output file - {} - {}",
                            path.display(),
                            e
                        ));
                    }
                };
                (None, Some(file))
            }
        }
        None => (None, None),
    };
    let format = if csv {
        Format::Csv
    } else if json {
        Format::Json
    } else {
        Format::Std
    };
    let writer = Writer {
        format,
        output,
        path,
        quiet,
    };
    set_writer(writer).expect("could not set writer");
    Ok(())
}

fn run() -> Result<()> {
    let opts = Opts::from_args();
    match opts.cmd {
        Command::Hunt {
            rules,
            path,

            mapping,
            rule,

            load_unknown,
            column_width,
            csv,
            extension,
            from,
            full,
            json,
            local,
            metadata,
            output,
            quiet,
            skip_errors,
            timezone,
            to,
        } => {
            init_writer(output, csv, json, quiet)?;
            if !opts.no_banner {
                print_title();
            }
            let mut rules = vec![rules];
            if let Some(rule) = rule {
                rules.extend(rule)
            };
            cs_eprintln!("[+] Loading rules...");
            let mut failed = 0;
            let mut count = 0;
            let mut rs = vec![];
            for path in &rules {
                for file in get_files(path, &None, skip_errors)? {
                    match load_rule(&file) {
                        Ok(mut r) => {
                            count += 1;
                            rs.append(&mut r)
                        }
                        Err(_) => {
                            failed += 1;
                        }
                    }
                }
            }
            if failed > 0 {
                cs_eprintln!(
                    "[+] Loaded {} detection rules ({} were not loaded)",
                    count,
                    failed
                );
            } else {
                cs_eprintln!("[+] Loaded {} detection rules", count);
            }
            let rules = rs;
            let mut hunter = Hunter::builder()
                .rules(rules)
                .mappings(mapping.unwrap_or_default())
                .load_unknown(load_unknown)
                .local(local)
                .skip_errors(skip_errors);
            if let Some(from) = from {
                hunter = hunter.from(from);
            }
            if let Some(timezone) = timezone {
                hunter = hunter.timezone(timezone);
            }
            if let Some(to) = to {
                hunter = hunter.to(to);
            }
            let hunter = hunter.build()?;
            let mut files = vec![];
            for path in &path {
                files.extend(get_files(path, &extension, skip_errors)?);
            }
            let mut detections = vec![];
            let pb = cli::init_progress_bar(files.len() as u64, "Hunting".to_string());
            for file in &files {
                pb.tick();
                detections.extend(hunter.hunt(file)?);
                pb.inc(1);
            }
            pb.finish();
            if csv {
                cli::print_csv(
                    &detections,
                    hunter.hunts(),
                    hunter.mappings(),
                    hunter.rules(),
                    local,
                    timezone,
                )?;
            } else if json {
                cli::print_json(&detections, hunter.rules(), local, timezone)?;
            } else {
                cli::print_detections(
                    &detections,
                    hunter.hunts(),
                    hunter.mappings(),
                    hunter.rules(),
                    column_width.unwrap_or(40),
                    full,
                    local,
                    metadata,
                    timezone,
                );
            }
            cs_eprintln!(
                "[+] {} Detections found on {} documents",
                detections.iter().map(|d| d.hits.len()).sum::<usize>(),
                detections.len()
            );
        }
        Command::Lint { path, kind } => {
            init_writer(None, false, false, false)?;
            if !opts.no_banner {
                print_title();
            }
            cs_eprintln!("[+] Validating supplied detection rules...");
            let mut count = 0;
            let mut failed = 0;
            for file in get_files(&path, &None, false)? {
                if let Err(e) = lint_rule(&kind, &file) {
                    failed += 1;
                    cs_eprintln!("[!] {}", e);
                    continue;
                }
                count += 1;
            }
            cs_eprintln!(
                "[+] Validated {} detection rules ({} were not loaded)",
                count,
                failed
            );
        }
        Command::Search {
            path,

            mut pattern,
            regexp,

            extension,
            from,
            ignore_case,
            json,
            load_unknown,
            local,
            output,
            quiet,
            skip_errors,
            tau,
            timestamp,
            timezone,
            to,
        } => {
            init_writer(output, false, json, quiet)?;
            if !opts.no_banner {
                print_title();
            }
            let mut paths = if regexp.is_some() || tau.is_some() {
                let mut scratch = pattern
                    .take()
                    .map(|p| vec![PathBuf::from(p)])
                    .unwrap_or_default();
                scratch.extend(path);
                scratch
            } else {
                path
            };
            if paths.is_empty() {
                paths.push(
                    std::env::current_dir().expect("could not get current working directory"),
                );
            }
            let mut files = vec![];
            for path in &paths {
                files.extend(get_files(path, &extension, skip_errors)?);
            }
            let mut searcher = Searcher::builder()
                .ignore_case(ignore_case)
                .load_unknown(load_unknown)
                .local(local)
                .skip_errors(skip_errors);
            if let Some(patterns) = regexp {
                searcher = searcher.patterns(patterns);
            } else if let Some(pattern) = pattern {
                searcher = searcher.patterns(vec![pattern]);
            }
            if let Some(from) = from {
                searcher = searcher.from(from);
            }
            if let Some(tau) = tau {
                searcher = searcher.tau(tau);
            }
            if let Some(timestamp) = timestamp {
                searcher = searcher.timestamp(timestamp);
            }
            if let Some(timezone) = timezone {
                searcher = searcher.timezone(timezone);
            }
            if let Some(to) = to {
                searcher = searcher.to(to);
            }
            let searcher = searcher.build()?;
            cs_eprintln!("[+] Searching event logs...");
            if json {
                cs_print!("[");
            }
            let mut hits = 0;
            for file in &files {
                for res in searcher.search(file)?.iter() {
                    let hit = match res {
                        Ok(hit) => hit,
                        Err(e) => {
                            if skip_errors {
                                continue;
                            }
                            anyhow::bail!("Failed to search file... - {}", e);
                        }
                    };
                    if json {
                        if !(hits == 0) {
                            cs_print!(",");
                        }
                        cs_print_json!(&hit)?;
                    } else {
                        cs_print_yaml!(&hit)?;
                    }
                    hits += 1;
                }
            }
            if json {
                cs_println!("]");
            }
            cs_println!("[+] Found {} matching log entries", hits);
        }
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        cs_eredln!("[x] {}", e);
        std::process::exit(1);
    }
}
