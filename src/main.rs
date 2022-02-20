use anyhow::Result;
use std::fs::File;

// TODO: Clean this, we have crudely split into a lib for testing purposes, this needs refinement.
use chainsaw::*;

use structopt::StructOpt;

#[derive(StructOpt)]
#[structopt(
    name = "chainsaw",
    about = "Rapidly Search and Hunt through windows event logs"
)]
struct Opts {
    #[structopt(subcommand)]
    cmd: Chainsaw,
}

#[derive(StructOpt)]
enum Chainsaw {
    /// Hunt through event logs using detection rules and builtin logic
    #[structopt(name = "hunt")]
    Hunt(hunt::HuntOpts),

    /// Search through event logs for specific event IDs and/or keywords
    #[structopt(name = "search")]
    Search(search::SearchOpts),

    /// Validate provided detection rules to ensure they load correctly
    #[structopt(name = "check")]
    Check(check::CheckOpts),
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

fn main() {
    // Get command line arguments
    let opt = Opts::from_args();
    // Load up the writer
    let writer = match &opt.cmd {
        Chainsaw::Hunt(args) => {
            let output = match &args.output {
                Some(path) => {
                    let file = match File::create(path) {
                        Ok(f) => f,
                        Err(e) => {
                            return exit_chainsaw(Err(anyhow::anyhow!(
                                "Unable to write to specified output file - {} - {}",
                                path.display(),
                                e
                            )));
                        }
                    };
                    Some(file)
                }
                None => None,
            };
            if args.json {
                write::Writer {
                    format: write::Format::Json,
                    output,
                    quiet: args.quiet,
                }
            } else if let Some(dir) = &args.csv {
                write::Writer {
                    format: write::Format::Csv(dir.clone()),
                    output,
                    quiet: args.quiet,
                }
            } else {
                write::Writer {
                    format: write::Format::Std,
                    output,
                    quiet: args.quiet,
                }
            }
        }
        Chainsaw::Search(args) => {
            let output = match &args.output {
                Some(path) => {
                    let file = match File::create(path) {
                        Ok(f) => f,
                        Err(e) => {
                            return exit_chainsaw(Err(anyhow::anyhow!(
                                "Unable to write to specified output file - {} - {}",
                                path.display(),
                                e
                            )));
                        }
                    };
                    Some(file)
                }
                None => None,
            };
            write::Writer {
                format: write::Format::Std,
                output,
                quiet: args.quiet,
            }
        }
        _ => write::Writer::default(),
    };
    write::set_writer(writer).unwrap();
    print_title();
    // Determine sub-command: hunt/search/check
    let result = match opt.cmd {
        Chainsaw::Search(args) => search::run_search(args),
        Chainsaw::Hunt(args) => hunt::run_hunt(args),
        Chainsaw::Check(args) => check::run_check(args),
    };
    exit_chainsaw(result);
}

fn exit_chainsaw(result: Result<String>) {
    // Handle successful/failed status messages returned by chainsaw
    std::process::exit(match result {
        Ok(m) => {
            cs_egreenln!("{}", m);
            0
        }
        Err(e) => {
            cs_eredln!("[!] Chainsaw exited: {}", e);
            1
        }
    })
}
