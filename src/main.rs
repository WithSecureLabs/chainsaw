#[macro_use]
extern crate chainsaw;

use std::collections::HashSet;
use std::fs::File;
use std::path::PathBuf;

use anyhow::Result;
use bytesize::ByteSize;
use chrono::NaiveDateTime;
use chrono_tz::Tz;

use structopt::StructOpt;

use chainsaw::{
    cli, get_files, lint_rule, load_rule, set_writer, Filter, Format, Hunter, RuleKind, RuleLevel,
    RuleStatus, Searcher, Writer,
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

        /// The paths containing event logs to hunt through.
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
        /// Restrict loaded rules to specified kinds.
        #[structopt(long = "kind", number_of_values = 1)]
        kinds: Vec<RuleKind>,
        /// Restrict loaded rules to specified levels.
        #[structopt(long = "level", number_of_values = 1)]
        levels: Vec<RuleLevel>,
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
        /// Restrict loaded rules to specified statuses.
        #[structopt(long = "status", number_of_values = 1)]
        statuses: Vec<RuleStatus>,
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
        /// The kind of rule to lint: chainsaw, sigma or stalker
        #[structopt(long = "kind")]
        kind: RuleKind,
        /// Output tau logic.
        #[structopt(short = "t", long = "tau")]
        tau: bool,
    },

    /// Search through event logs for specific event IDs and/or keywords
    Search {
        /// A pattern to search for.
        #[structopt(required_unless_one=&["regexp", "tau"])]
        pattern: Option<String>,

        /// The paths containing event logs to hunt through.
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
            kinds,
            levels,
            local,
            metadata,
            output,
            quiet,
            skip_errors,
            statuses,
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

            cs_eprintln!(
                "[+] Loading event logs from: {}",
                path.iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );

            cs_eprintln!(
                "[+] Loading detection rules from: {}",
                rules
                    .iter()
                    .map(|r| r.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            let kinds: Option<HashSet<RuleKind>> = if kinds.is_empty() {
                None
            } else {
                Some(HashSet::from_iter(kinds.into_iter()))
            };
            let levels: Option<HashSet<RuleLevel>> = if levels.is_empty() {
                None
            } else {
                Some(HashSet::from_iter(levels.into_iter()))
            };
            let statuses: Option<HashSet<RuleStatus>> = if statuses.is_empty() {
                None
            } else {
                Some(HashSet::from_iter(statuses.into_iter()))
            };
            let mut failed = 0;
            let mut count = 0;
            let mut rs = vec![];
            for path in &rules {
                for file in get_files(path, &None, skip_errors)? {
                    match load_rule(&file, &mapping.is_some(), &kinds, &levels, &statuses) {
                        Ok(mut r) => {
                            if !r.is_empty() {
                                count += 1;
                                rs.append(&mut r)
                            }
                        }
                        Err(e) => {
                            // Hacky way of exposing rule types from load_rule function
                            if e.to_string() == "sigma-no-mapping" {
                                return Err(anyhow::anyhow!(
                                    "No mapping file specified for provided Sigma rules, specify one with the '-m' flag",
                                ));
                            }
                            failed += 1;
                        }
                    }
                }
            }
            if count == 0 {
                return Err(anyhow::anyhow!(
                    "No valid detection rules were found in the provided paths",
                ));
            }
            if failed > 0 {
                cs_eprintln!(
                    "[+] Loaded {} detection rules ({} not loaded)",
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
            let mut size = ByteSize::mb(0);
            for path in &path {
                let res = get_files(path, &extension, skip_errors)?;
                for i in &res {
                    size += i.metadata()?.len();
                }
                files.extend(res);
            }
            if files.is_empty() {
                return Err(anyhow::anyhow!(
                    "No event logs were found in the provided paths",
                ));
            } else {
                cs_eprintln!("[+] Loaded {} EVTX files ({})", files.len(), size);
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
                cli::print_csv(&detections, hunter.hunts(), hunter.rules(), local, timezone)?;
            } else if json {
                cli::print_json(&detections, hunter.rules(), local, timezone)?;
            } else {
                cli::print_detections(
                    &detections,
                    hunter.hunts(),
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
        Command::Lint { path, kind, tau } => {
            init_writer(None, false, false, false)?;
            if !opts.no_banner {
                print_title();
            }
            cs_eprintln!("[+] Validating as {} for supplied detection rules...", kind);
            let mut count = 0;
            let mut failed = 0;
            for file in get_files(&path, &None, false)? {
                match lint_rule(&kind, &file) {
                    Ok(filters) => {
                        if tau {
                            cs_eprintln!("[+] Rule {}:", file.to_string_lossy());
                            for filter in filters {
                                let yaml = match filter {
                                    Filter::Detection(mut d) => {
                                        d.expression = tau_engine::core::optimiser::coalesce(
                                            d.expression,
                                            &d.identifiers,
                                        );
                                        d.identifiers.clear();
                                        d.expression =
                                            tau_engine::core::optimiser::shake(d.expression);
                                        d.expression =
                                            tau_engine::core::optimiser::rewrite(d.expression);
                                        d.expression =
                                            tau_engine::core::optimiser::matrix(d.expression);
                                        serde_yaml::to_string(&d)?
                                    }
                                    Filter::Expression(_) => {
                                        cs_eyellowln!("[!] Tau does not support visual representation of expressions");
                                        continue;
                                    }
                                };
                                println!("{}", yaml);
                            }
                        }
                    }
                    Err(e) => {
                        failed += 1;
                        let file_name = match file
                            .display()
                            .to_string()
                            .strip_prefix(&path.display().to_string())
                        {
                            Some(e) => e.to_string(),
                            None => file.display().to_string(),
                        };
                        cs_eprintln!("[!] {}: {}", file_name, e);
                        continue;
                    }
                }
                count += 1;
            }
            cs_eprintln!(
                "[+] Validated {} detection rules out of {}",
                count,
                count + failed
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
            let mut size = ByteSize::mb(0);
            for path in &paths {
                let res = get_files(path, &extension, skip_errors)?;
                for i in &res {
                    size += i.metadata()?.len();
                }
                files.extend(res);
            }

            if files.is_empty() {
                return Err(anyhow::anyhow!(
                    "No event logs were found in the provided paths",
                ));
            } else {
                cs_eprintln!("[+] Loaded {} EVTX files ({})", files.len(), size);
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
                        if hits != 0 {
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
