#[macro_use]
extern crate anyhow;

pub(crate) use anyhow::Result;

pub use file::{evtx, get_files, Reader};
pub use hunt::{Detection, Hunter, HunterBuilder};
pub use rule::{lint_rule, load_rule, Kind as RuleKind};
pub use search::{Searcher, SearcherBuilder};
pub use write::{set_writer, Format, Writer, WRITER};

#[macro_use]
mod write;

pub mod cli;
mod ext;
mod file;
mod hunt;
mod rule;
mod search;
