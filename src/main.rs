#[macro_use]
extern crate chainsaw;

use rayon::prelude::*;
use std::fs::{self, File};
use std::io::BufRead;
use std::path::PathBuf;
use std::sync::Arc;
use std::{collections::HashSet, io::BufReader};

use anyhow::{Context, Result};
use bytesize::ByteSize;
use chrono::NaiveDateTime;
use chrono_tz::Tz;

use clap::{ArgAction, Parser, Subcommand};

use chainsaw::{
    cli, get_files, lint as lint_rule, load as load_rule, set_writer, Document, Filter, Format,
    Hunter, Reader, RuleKind, RuleLevel, RuleStatus, Searcher, ShimcacheAnalyser, SrumAnalyser,
    Writer,
};

#[derive(Parser)]
#[clap(
    name = "chainsaw",
    about = "Rapidly work with Forensic Artefacts",
    after_help = r"Examples:

    Hunt with Sigma and Chainsaw Rules:
        ./chainsaw hunt evtx_attack_samples/ -s sigma/ --mapping mappings/sigma-event-logs-all.yml -r rules/

    Hunt with Sigma rules and output in JSON:
        ./chainsaw hunt evtx_attack_samples/ -s sigma/ --mapping mappings/sigma-event-logs-all.yml --json

    Search for the case-insensitive word 'mimikatz':
        ./chainsaw search mimikatz -i evtx_attack_samples/

    Search for Powershell Script Block Events (EventID 4014):
        ./chainsaw search -t 'Event.System.EventID: =4104' evtx_attack_samples/
    ",
    version
)]
struct Args {
    /// Hide Chainsaw's banner.
    #[arg(long)]
    no_banner: bool,
    /// Limit the thread number (default: num of CPUs)
    #[arg(long)]
    num_threads: Option<usize>,
    /// Print verbose output.
    #[arg(short = 'v', action = ArgAction::Count)]
    verbose: u8,
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Dump artefacts into a different format.
    Dump {
        /// The paths containing files to dump.
        path: Vec<PathBuf>,

        /// Dump in json format.
        #[arg(group = "format", short = 'j', long = "json")]
        json: bool,
        /// Print the output in jsonl format.
        #[arg(group = "format", long = "jsonl")]
        jsonl: bool,
        /// Allow chainsaw to try and load files it cannot identify.
        #[arg(long = "load-unknown")]
        load_unknown: bool,
        /// Only dump files with the provided extension.
        #[arg(long = "extension")]
        extension: Option<String>,
        /// A path to output results to.
        #[arg(short = 'o', long = "output")]
        output: Option<PathBuf>,
        /// Suppress informational output.
        #[arg(short = 'q')]
        quiet: bool,
        /// Continue to hunt when an error is encountered.
        #[arg(long = "skip-errors")]
        skip_errors: bool,

        // MFT Specific Options
        /// Attempt to decode all extracted data streams from Hex to UTF-8
        #[arg(long = "decode-data-streams", help_heading = "MFT Specific Options")]
        decode_data_streams: bool,
        /// Extracted data streams will be decoded and written to this directory
        #[arg(long = "data-streams-directory", help_heading = "MFT Specific Options")]
        data_streams_directory: Option<PathBuf>,
    },

    /// Hunt through artefacts using detection rules for threat detection.
    Hunt {
        /// The path to a collection of rules to use for hunting.
        rules: Option<PathBuf>,

        /// The paths containing files to load and hunt through.
        path: Vec<PathBuf>,

        /// A mapping file to tell Chainsaw how to use third-party rules.
        #[arg(short = 'm', long = "mapping", number_of_values = 1)]
        mapping: Option<Vec<PathBuf>>,
        /// A path containing additional rules to hunt with.
        #[arg(short = 'r', long = "rule", number_of_values = 1)]
        rule: Option<Vec<PathBuf>>,

        /// Cache results to disk to reduce memory usage at the cost of performance.
        #[arg(
            short = 'c',
            long = "cache-to-disk",
            requires = "jsonl",
            conflicts_with = "json"
        )]
        cache: bool,
        /// Set the column width for the tabular output.
        #[arg(long = "column-width", conflicts_with = "json")]
        column_width: Option<u32>,
        /// Print the output in csv format.
        #[arg(group = "format", long = "csv", requires = "output")]
        csv: bool,
        /// Only hunt through files with the provided extension.
        #[arg(long = "extension", number_of_values = 1)]
        extension: Option<Vec<String>>,
        /// The timestamp to hunt from. Drops any documents older than the value provided.
        /// (YYYY-MM-ddTHH:mm:SS)
        #[arg(long = "from")]
        from: Option<NaiveDateTime>,
        /// Print the full values for the tabular output.
        #[arg(long = "full", conflicts_with = "json")]
        full: bool,
        /// Print the output in json format.
        #[arg(group = "format", short = 'j', long = "json")]
        json: bool,
        /// Print the output in jsonl format.
        #[arg(group = "format", long = "jsonl")]
        jsonl: bool,
        /// Restrict loaded rules to specified kinds.
        #[arg(long = "kind", number_of_values = 1)]
        kind: Vec<RuleKind>,
        /// Restrict loaded rules to specified levels.
        #[arg(long = "level", number_of_values = 1)]
        level: Vec<RuleLevel>,
        /// Allow chainsaw to try and load files it cannot identify.
        #[arg(long = "load-unknown")]
        load_unknown: bool,
        /// Output the timestamp using the local machine's timestamp.
        #[arg(long = "local", group = "tz")]
        local: bool,
        /// Display additional metadata in the tablar output.
        #[arg(long = "metadata", conflicts_with = "json")]
        metadata: bool,
        /// A path to output results to.
        #[arg(short = 'o', long = "output")]
        output: Option<PathBuf>,
        /// Print the output in log like format.
        #[arg(group = "format", long = "log")]
        log: bool,
        /// (BETA) Enable preprocessing, which can result in increased performance.
        #[arg(long = "preprocess")]
        preprocess: bool,
        /// Suppress informational output.
        #[arg(short = 'q')]
        quiet: bool,
        /// A path containing Sigma rules to hunt with.
        #[arg(
            short = 's',
            long = "sigma",
            number_of_values = 1,
            requires = "mapping"
        )]
        sigma: Option<Vec<PathBuf>>,
        /// Continue to hunt when an error is encountered.
        #[arg(long = "skip-errors")]
        skip_errors: bool,
        /// Restrict loaded rules to specified statuses.
        #[arg(long = "status", number_of_values = 1)]
        status: Vec<RuleStatus>,
        /// Output the timestamp using the timezone provided.
        #[arg(long = "timezone", group = "tz")]
        timezone: Option<Tz>,
        /// The timestamp to hunt up to. Drops any documents newer than the value provided.
        /// (YYYY-MM-ddTHH:mm:SS)
        #[arg(long = "to")]
        to: Option<NaiveDateTime>,
    },

    /// Lint provided rules to ensure that they load correctly
    Lint {
        /// The path to a collection of rules.
        path: PathBuf,
        /// The kind of rule to lint: chainsaw, sigma or stalker
        #[arg(long = "kind")]
        kind: RuleKind,
        /// Output tau logic.
        #[arg(short = 't', long = "tau")]
        tau: bool,
    },

    /// Search through forensic artefacts for keywords or patterns.
    Search {
        /// A string or regular expression pattern to search for.
        /// Not used when -e or -t is specified.
        #[arg(required_unless_present_any=&["additional_pattern", "tau"])]
        pattern: Option<String>,

        /// The paths containing files to load and hunt through.
        path: Vec<PathBuf>,

        /// A string or regular expression pattern to search for.
        #[arg(
            short = 'e',
            long = "regex",
            value_name = "pattern",
            number_of_values = 1
        )]
        additional_pattern: Option<Vec<String>>,

        /// Only search through files with the provided extension.
        #[arg(long = "extension", number_of_values = 1)]
        extension: Option<Vec<String>>,
        /// The timestamp to search from. Drops any documents older than the value provided.
        /// (YYYY-MM-ddTHH:mm:SS)
        #[arg(long = "from", requires = "timestamp")]
        from: Option<NaiveDateTime>,
        /// Ignore the case when searching patterns
        #[arg(short = 'i', long = "ignore-case")]
        ignore_case: bool,
        /// Print the output in json format.
        #[arg(short = 'j', long = "json")]
        json: bool,
        /// Print the output in jsonl format.
        #[arg(group = "format", long = "jsonl")]
        jsonl: bool,
        /// Allow chainsaw to try and load files it cannot identify.
        #[arg(long = "load-unknown")]
        load_unknown: bool,
        /// Output the timestamp using the local machine's timestamp.
        #[arg(long = "local", group = "tz")]
        local: bool,
        /// Require any of the provided patterns to be found to constitute a match.
        #[arg(long = "match-any")]
        match_any: bool,
        /// The path to output results to.
        #[arg(short = 'o', long = "output")]
        output: Option<PathBuf>,
        /// Suppress informational output.
        #[arg(short = 'q')]
        quiet: bool,
        /// Continue to search when an error is encountered.
        #[arg(long = "skip-errors")]
        skip_errors: bool,
        /// Tau expressions to search with. e.g. 'Event.System.EventID: =4104'.
        /// Multiple conditions are logical ANDs unless the 'match-any' flag is specified
        #[arg(short = 't', long = "tau", number_of_values = 1)]
        tau: Option<Vec<String>>,
        /// The field that contains the timestamp.
        #[arg(long = "timestamp")]
        timestamp: Option<String>,
        /// Output the timestamp using the timezone provided.
        #[arg(long = "timezone", group = "tz")]
        timezone: Option<Tz>,
        /// The timestamp to search up to. Drops any documents newer than the value provided.
        /// (YYYY-MM-ddTHH:mm:SS)
        #[arg(long = "to", requires = "timestamp")]
        to: Option<NaiveDateTime>,
    },

    /// Perform various analyses on artefacts
    Analyse {
        #[command(subcommand)]
        cmd: AnalyseCommand,
    },
}

#[derive(Subcommand)]
enum AnalyseCommand {
    /// Create an execution timeline from the shimcache with optional amcache enrichments
    Shimcache {
        /// The path to the shimcache artefact (SYSTEM registry file)
        shimcache: PathBuf,
        /// A string or regular expression for detecting shimcache entries whose timestamp matches their insertion time
        #[arg(
            short = 'e',
            long = "regex",
            value_name = "pattern",
            number_of_values = 1
        )]
        additional_pattern: Option<Vec<String>>,
        /// The path to a newline delimited file containing regex patterns for detecting shimcache entries whose timestamp matches their insertion time
        #[arg(short = 'r', long = "regexfile")]
        regex_file: Option<PathBuf>,
        /// The path to output the result csv file
        #[arg(short = 'o', long = "output")]
        output: Option<PathBuf>,
        /// The path to the amcache artefact (Amcache.hve) for timeline enrichment
        #[arg(short = 'a', long = "amcache")]
        amcache: Option<PathBuf>,
        /// Enable near timestamp pair detection between shimcache and amcache for finding additional insertion timestamps for shimcache entries
        #[arg(short = 'p', long = "tspair", requires = "amcache")]
        ts_near_pair_matching: bool,
    },
    /// Analyse the SRUM database
    Srum {
        /// The path to the SRUM database
        srum_path: PathBuf,
        /// The path to the SOFTWARE hive
        #[arg(short = 's', long = "software")]
        software_hive_path: PathBuf,
        /// Only output details about the SRUM database
        #[arg(long = "stats-only")]
        stats_only: bool,
        /// Suppress informational output.
        #[arg(short = 'q')]
        quiet: bool,
        /// Save the output to a file
        #[arg(short = 'o', long = "output")]
        output: Option<PathBuf>,
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
    By WithSecure Countercept (@FranticTyping, @AlexKornitzer)
"
    );
}

fn resolve_col_width() -> Option<u32> {
    use terminal_size::{terminal_size, Width};
    if let Some((Width(w), _)) = terminal_size() {
        match w {
            50..=120 => Some(20),
            121..=239 => Some(30),
            240..=340 => Some(50),
            341..=430 => Some(90),
            431..=550 => Some(130),
            551.. => Some(160),
            _ => None,
        }
    } else {
        None
    }
}

fn init_writer(
    output: Option<PathBuf>,
    csv: bool,
    json: bool,
    quiet: bool,
    verbose: u8,
) -> crate::Result<()> {
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
        verbose,
    };
    set_writer(writer).expect("could not set writer");
    Ok(())
}

fn run() -> Result<()> {
    let args = Args::parse();
    if let Some(num_threads) = args.num_threads {
        rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build_global()?;
    }
    match args.cmd {
        Command::Dump {
            path,

            json,
            jsonl,
            load_unknown,
            extension,
            output,
            quiet,
            skip_errors,
            decode_data_streams,
            data_streams_directory,
        } => {
            init_writer(output, false, json, quiet, args.verbose)?;
            if !args.no_banner {
                print_title();
            }
            cs_eprintln!(
                "[+] Dumping the contents of forensic artefacts from: {} (extensions: {})",
                path.iter()
                    .map(|r| r.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                extension.clone().unwrap_or("*".to_string())
            );

            if json {
                cs_print!("[");
            }

            let mut files = vec![];
            let mut size = ByteSize::mb(0);
            let mut extensions: Option<HashSet<String>> = None;
            if let Some(extension) = extension {
                extensions = Some(HashSet::from([extension]));
            }
            for path in &path {
                let res = get_files(path, &extensions, skip_errors)?;
                for i in &res {
                    size += i.metadata()?.len();
                }
                files.extend(res);
            }
            if files.is_empty() {
                return Err(anyhow::anyhow!(
                    "No compatible files were found in the provided paths",
                ));
            } else {
                cs_eprintln!("[+] Loaded {} forensic artefacts ({})", files.len(), size);
            }

            let mut first = true;
            for path in &files {
                let mut reader = Reader::load(
                    path,
                    load_unknown,
                    skip_errors,
                    decode_data_streams,
                    data_streams_directory.clone(),
                )?;

                // We try to keep the reader and parser as generic as possible.
                // However in some cases we need to pass artefact specific arguments to the parser.
                // If the argument is not relevant for the artefact, it is ignored.
                for result in reader.documents() {
                    let document = match result {
                        Ok(document) => document,
                        Err(e) => {
                            if skip_errors {
                                cs_eyellowln!(
                                    "[!] failed to parse document '{}' - {}\n",
                                    path.display(),
                                    e
                                );
                                continue;
                            }
                            return Err(e);
                        }
                    };
                    let value = match document {
                        Document::Evtx(evtx) => evtx.data,
                        Document::Hve(json)
                        | Document::Json(json)
                        | Document::Xml(json)
                        | Document::Mft(json)
                        | Document::Esedb(json) => json,
                    };

                    if json {
                        if first {
                            first = false;
                        } else {
                            cs_println!(",");
                        }
                        cs_print_json_pretty!(&value)?;
                    } else if jsonl {
                        cs_print_json!(&value)?;
                        cs_println!();
                    } else {
                        cs_println!("---");
                        cs_print_yaml!(&value)?;
                    }
                }
            }
            if json {
                cs_println!("]");
            }
            cs_eprintln!("[+] Done");
        }
        Command::Hunt {
            rules,
            mut path,

            mapping,
            rule,

            load_unknown,
            cache,
            mut column_width,
            csv,
            extension,
            from,
            full,
            json,
            jsonl,
            kind,
            level,
            local,
            metadata,
            output,
            log,
            preprocess,
            quiet,
            sigma,
            skip_errors,
            status,
            timezone,
            to,
        } => {
            if column_width.is_none() {
                column_width = resolve_col_width();
            }
            // CSV must be a folder when hunting due to the complexity of the output
            if csv {
                if let Some(path) = &output {
                    if path.is_file() {
                        let writer = Writer {
                            quiet,
                            ..Default::default()
                        };
                        set_writer(writer).expect("could not set writer");
                        if !args.no_banner {
                            print_title();
                        }
                        anyhow::bail!("Unable to create output directory");
                    }
                }
            }
            init_writer(output.clone(), csv, json, quiet, args.verbose)?;
            if !args.no_banner {
                print_title();
            }
            let mut rs = vec![];
            if rule.is_some() || sigma.is_some() {
                if let Some(rules) = rules {
                    let mut paths = vec![rules];
                    paths.extend(path);
                    path = paths;
                }
            } else if let Some(rules) = rules {
                rs = vec![rules];
            }
            let mut rules = rs;
            if let Some(rule) = rule {
                rules.extend(rule)
            };
            let sigma = sigma.unwrap_or_default();

            cs_eprintln!(
                "[+] Loading detection rules from: {}",
                rules
                    .iter()
                    .chain(sigma.iter())
                    .map(|r| r.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            let kinds: Option<HashSet<RuleKind>> = if kind.is_empty() {
                None
            } else {
                Some(HashSet::from_iter(kind))
            };
            let levels: Option<HashSet<RuleLevel>> = if level.is_empty() {
                None
            } else {
                Some(HashSet::from_iter(level))
            };
            let statuses: Option<HashSet<RuleStatus>> = if status.is_empty() {
                None
            } else {
                Some(HashSet::from_iter(status))
            };
            let mut failed = 0;
            let mut count = 0;
            let mut rs = vec![];
            for path in &rules {
                for file in get_files(path, &None, skip_errors)? {
                    cs_debug!("[*] Loading chainsaw rule - {}", file.display());
                    match load_rule(RuleKind::Chainsaw, &file, &kinds, &levels, &statuses) {
                        Ok(r) => {
                            if !r.is_empty() {
                                count += 1;
                                rs.extend(r)
                            }
                        }
                        Err(_) => {
                            failed += 1;
                        }
                    }
                }
            }
            for path in &sigma {
                for file in get_files(path, &None, skip_errors)? {
                    cs_debug!("[*] Loading sigma rule - {}", file.display());
                    match load_rule(RuleKind::Sigma, &file, &kinds, &levels, &statuses) {
                        Ok(r) => {
                            if !r.is_empty() {
                                count += 1;
                                rs.extend(r)
                            }
                        }
                        Err(_) => {
                            failed += 1;
                        }
                    }
                }
            }
            if failed > 500 && sigma.is_empty() {
                cs_eyellowln!("[!] {} rules failed to load, ensure Sigma rule paths are specified with the '-s' flag", failed);
            }
            if count == 0 {
                return Err(anyhow::anyhow!(
                    "No valid detection rules were found in the provided paths",
                ));
            }
            if failed > 0 {
                cs_eyellowln!(
                    "[!] Loaded {} detection rules ({} not loaded)",
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
                .preprocess(preprocess)
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

            /* if no user-defined extensions are specified, then we parse rules and
            mappings to build a list of file extensions that should be loaded */
            let mut scratch = HashSet::new();
            let message;
            let exts = if load_unknown {
                message = "*".to_string();
                None
            } else {
                scratch.extend(hunter.extensions());
                if scratch.is_empty() {
                    return Err(anyhow::anyhow!(
                        "No valid file extensions for the 'kind' specified in the mapping or rules files"
                    ));
                }
                if let Some(e) = extension {
                    // User has provided specific extensions
                    scratch = scratch
                        .intersection(&HashSet::from_iter(e.iter().cloned()))
                        .cloned()
                        .collect();
                    if scratch.is_empty() {
                        return Err(anyhow::anyhow!(
                        "The specified file extension is not supported. Use --load-unknown to force loading",
                    ));
                    }
                };
                message = scratch
                    .iter()
                    .map(|x| format!(".{}", x))
                    .collect::<Vec<_>>()
                    .join(", ");
                Some(scratch)
            };

            cs_eprintln!(
                "[+] Loading forensic artefacts from: {} (extensions: {})",
                path.iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                message
            );

            let mut files = vec![];
            let mut size = ByteSize::mb(0);
            for path in &path {
                let res = get_files(path, &exts, skip_errors)?;
                for i in &res {
                    size += i.metadata()?.len();
                }
                files.extend(res);
            }
            if files.is_empty() {
                return Err(anyhow::anyhow!(
                    "No compatible files were found in the provided paths",
                ));
            } else {
                cs_eprintln!("[+] Loaded {} forensic artefacts ({})", files.len(), size);
            }
            let mut hits = 0;
            let mut documents = 0;
            let mut detections = vec![];
            let pb = cli::init_progress_bar(
                files.len() as u64,
                "".to_string(),
                args.verbose != 0,
                "Hunting".to_string(),
            );
            for file in &files {
                cs_debug!("[*] Hunting through file - {}", file.display());
                pb.set_message(format!("[+] Current Artifact: {}\n", file.display()));
                let cache = if cache {
                    match tempfile::tempfile() {
                        Ok(f) => Some(f),
                        Err(e) => {
                            anyhow::bail!("Failed to create cache on disk - {}", e);
                        }
                    }
                } else {
                    None
                };
                let scratch = hunter.hunt(file, &cache).with_context(|| {
                    format!("Failed to hunt through file '{}' (Use --skip-errors to continue processing)", file.to_string_lossy())
                })?;
                hits += scratch.iter().map(|d| d.hits.len()).sum::<usize>();
                documents += scratch.len();
                if jsonl {
                    cli::print_jsonl(
                        &scratch,
                        hunter.hunts(),
                        hunter.rules(),
                        local,
                        timezone,
                        cache,
                    )?;
                } else {
                    detections.extend(scratch);
                }
                pb.inc(1);
            }
            pb.finish();
            if csv {
                cli::print_csv(&detections, hunter.hunts(), hunter.rules(), local, timezone)?;
            } else if json {
                if output.is_some() {
                    cs_eprintln!("[+] Writing results to output file...");
                }
                cli::print_json(&detections, hunter.hunts(), hunter.rules(), local, timezone)?;
            } else if jsonl {
                // Work already done
            } else if log {
                cli::print_log(&detections, hunter.hunts(), hunter.rules(), local, timezone)?;
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
            cs_eprintln!("\n[+] {} Detections found on {} documents", hits, documents,);
        }
        Command::Lint { path, kind, tau } => {
            init_writer(None, false, false, false, args.verbose)?;
            if !args.no_banner {
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
                                cs_println!("{}", yaml);
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
            additional_pattern,

            extension,
            from,
            ignore_case,
            json,
            jsonl,
            load_unknown,
            local,
            match_any,
            output,
            quiet,
            skip_errors,
            tau,
            timestamp,
            timezone,
            to,
        } => {
            init_writer(output, false, json, quiet, args.verbose)?;
            if !args.no_banner {
                print_title();
            }
            let mut paths = if additional_pattern.is_some() || tau.is_some() {
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

            let types = extension.as_ref().map(|e| HashSet::from_iter(e.clone()));
            let mut files = vec![];
            let mut size = ByteSize::mb(0);
            for path in &paths {
                let res = get_files(path, &types, skip_errors)?;
                for i in &res {
                    size += i.metadata()?.len();
                }
                files.extend(res);
            }
            if let Some(ext) = &extension {
                cs_eprintln!(
                    "[+] Loading forensic artefacts from: {} (extensions: {})",
                    paths
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                    ext.iter()
                        .map(|x| format!(".{}", x))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            } else {
                cs_eprintln!(
                    "[+] Loading forensic artefacts from: {}",
                    paths
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                )
            };

            if files.is_empty() {
                return Err(anyhow::anyhow!(
                    "No forensic artefacts were found in the provided paths",
                ));
            } else {
                cs_eprintln!("[+] Loaded {} forensic files ({})", files.len(), size);
            }
            let mut searcher = Searcher::builder()
                .ignore_case(ignore_case)
                .load_unknown(load_unknown)
                .local(local)
                .skip_errors(skip_errors)
                .match_any(match_any);
            if let Some(patterns) = additional_pattern {
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
            cs_eprintln!("[+] Searching forensic artefacts...");
            if json {
                cs_print!("[");
            }

            let total_hits = Arc::new(std::sync::Mutex::new(0));

            files.par_iter().try_for_each(|file| {
                match searcher.search(file) {
                    Ok(mut results) => {
                        for res in results.iter() {
                            let hit = match res {
                                Ok(hit) => hit,
                                Err(e) => {
                                    return Err(anyhow::anyhow!(
                                        "Failed to search file {} - {} (Use --skip-errors to continue processing)",
                                        file.display(),
                                        e
                                    ));
                                }
                            };

                            // Create lock before dealing with JSON print sequence
                            let mut hit_count = total_hits.lock().expect("Failed to lock total_hits mutex");

                            if json {
                                if *hit_count != 0 {
                                    cs_print!(",");
                                }
                                cs_print_json!(&hit)?;
                            } else if jsonl {
                                cs_print_json!(&hit)?;
                                cs_println!();
                            } else {
                                cs_println!("---");
                                cs_print_yaml!(&hit)?;
                            }
                            *hit_count += 1;
                        }
                    }
                    Err(e) => {
                        return Err(anyhow::anyhow!(
                            "Failed to search file {} - {} (Use --skip-errors to continue processing)",
                            file.display(),
                            e
                        ));
                    }
                }


                Ok(())
            })?;

            if json {
                cs_println!("]");
            }
            cs_eprintln!(
                "[+] Found {} hits",
                *total_hits.lock().expect("Failed to lock total_hits mutex")
            );
        }
        Command::Analyse { cmd } => {
            match cmd {
                AnalyseCommand::Shimcache {
                    additional_pattern,
                    amcache,
                    output,
                    regex_file,
                    shimcache,
                    ts_near_pair_matching,
                } => {
                    if !args.no_banner {
                        print_title();
                    }
                    init_writer(output.clone(), true, false, false, args.verbose)?;
                    let shimcache_analyser = ShimcacheAnalyser::new(shimcache, amcache);

                    // Load regex
                    let mut regex_patterns: Vec<String> = Vec::new();
                    if let Some(regex_file) = regex_file {
                        let mut file_regex_patterns = BufReader::new(File::open(&regex_file)?)
                            .lines()
                            .collect::<Result<Vec<_>, _>>()?;
                        cs_eprintln!(
                            "[+] Regex file with {} pattern(s) loaded from {:?}",
                            file_regex_patterns.len(),
                            fs::canonicalize(&regex_file).expect("could not get absolute path")
                        );
                        regex_patterns.append(&mut file_regex_patterns);
                    }
                    if let Some(mut additional_patterns) = additional_pattern {
                        regex_patterns.append(&mut additional_patterns);
                    }

                    // Do analysis
                    let timeline = shimcache_analyser
                        .amcache_shimcache_timeline(&regex_patterns, ts_near_pair_matching)?;
                    cli::print_shimcache_analysis_csv(&timeline)?;

                    if let Some(output_path) = output {
                        cs_eprintln!(
                            "[+] Saved output to {:?}",
                            std::fs::canonicalize(output_path)
                                .expect("could not get absolute path")
                        );
                    }
                }
                AnalyseCommand::Srum {
                    srum_path,
                    software_hive_path,
                    stats_only,
                    quiet,
                    output,
                } => {
                    init_writer(output.clone(), false, true, quiet, args.verbose)?;
                    if !args.no_banner {
                        print_title();
                    }
                    let srum_analyser = SrumAnalyser::new(srum_path, software_hive_path);
                    match srum_analyser.parse_srum_database() {
                        Ok(srum_db_info) => {
                            if stats_only {
                                cs_eprintln!(
                                    "[+] Details about the tables related to the SRUM extensions:"
                                );
                                cs_println!(
                                    "{}",
                                    srum_db_info
                                        .table_details
                                        .to_string()
                                        .trim_end_matches('\n')
                                );
                            } else {
                                cs_eprintln!(
                                    "[+] Details about the tables related to the SRUM extensions:\n{}",
                                    srum_db_info.table_details.to_string().trim_end_matches('\n')
                                );

                                let json = srum_db_info.db_content;
                                cs_eprintln!("[+] SRUM database parsed successfully");
                                if let Some(output_path) = output {
                                    cs_eprintln!(
                                        "[+] Saving output to {:?}",
                                        std::fs::canonicalize(&output_path)
                                            .expect("could not get absolute path")
                                    );
                                    cs_print_json!(&json)?;
                                    cs_eprintln!(
                                        "[+] Saved output to {:?}",
                                        std::fs::canonicalize(&output_path)
                                            .expect("could not get absolute path")
                                    );
                                } else {
                                    cs_print_json!(&json)?;
                                }
                            }
                        }
                        Err(err) => cs_eredln!("[!] Error parsing SRUM database: {:?}", err),
                    }
                }
            }
        }
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        if let Some(cause) = e.chain().nth(1) {
            cs_eredln!("[x] {} - {}", e, cause);
        } else {
            cs_eredln!("[x] {}", e);
        }
        std::process::exit(1);
    }
}
