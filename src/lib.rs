#[macro_use]
extern crate anyhow;

pub(crate) use anyhow::Result;

pub use analyse::shimcache::ShimcacheAnalyzer;
pub use file::{evtx, get_files, Document, Kind as FileKind, Reader};
pub use hunt::{Hunter, HunterBuilder};
pub use rule::{
    lint, load, sigma, Filter, Kind as RuleKind, Level as RuleLevel, Status as RuleStatus,
};
pub use search::{Searcher, SearcherBuilder};
pub use write::{set_writer, Format, Writer, WRITER};

#[macro_use]
mod write;

mod analyse;
pub mod cli;
mod ext;
mod file;
mod hunt;
mod rule;
mod search;
mod value;
