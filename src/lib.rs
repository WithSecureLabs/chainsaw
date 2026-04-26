#[macro_use]
extern crate anyhow;

pub(crate) use anyhow::Result;

pub use analyse::gaps::{FileGapReport, GapAnalyser, print_text_report as print_gap_text_report};
pub use analyse::shimcache::ShimcacheAnalyser;
pub use analyse::srum::SrumAnalyser;
pub use file::{Document, Kind as FileKind, Reader, evtx, get_files};
pub use hunt::{Hunter, HunterBuilder};
pub use rule::{
    Filter, Kind as RuleKind, Level as RuleLevel, Status as RuleStatus, lint, load, sigma,
};
pub use search::{Searcher, SearcherBuilder};
pub use write::{Format, Writer, set_writer, writer};

#[macro_use]
mod write;

mod analyse;
pub mod cli;
mod ext;
mod file;
mod hunt;
pub mod rule;
mod search;
mod value;
