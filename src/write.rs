use std::path::PathBuf;

use anyhow::Result;

pub static mut WRITER: Writer = Writer {
    format: Format::Std,
    quiet: false,
};

pub enum Format {
    Std,
    Json,
    Csv(PathBuf),
}

impl Default for Format {
    fn default() -> Self {
        Format::Std
    }
}

#[derive(Default)]
pub struct Writer {
    pub format: Format,
    pub quiet: bool,
}

pub fn set_writer(writer: Writer) -> Result<()> {
    set_writer_inner(|| writer)
}

fn set_writer_inner<F>(make_writer: F) -> Result<()>
where
    F: FnOnce() -> Writer,
{
    unsafe {
        WRITER = make_writer();
    }
    Ok(())
}

macro_rules! cs_print {
    ($($arg:tt)*) => ({
        print!($($arg)*);
    })
}

macro_rules! cs_println {
    ($($arg:tt)*) => ({
        println!($($arg)*);
    })
}

macro_rules! cs_eprintln {
    ($($arg:tt)*) => ({
        unsafe {
            if !$crate::write::WRITER.quiet {
                eprintln!($($arg)*);
            }
        }
    })
}

macro_rules! cs_print_json {
    ($value:expr) => {{
        use std::io::Write;
        $crate::serde_json::to_writer(std::io::stdout(), $value)?;
        std::io::stdout().flush()
    }};
}

macro_rules! cs_print_yaml {
    ($value:expr) => {{
        use std::io::Write;
        $crate::serde_yaml::to_writer(std::io::stdout(), $value)?;
        println!();
        std::io::stdout().flush()
    }};
}

macro_rules! cs_print_table {
    ($table:ident) => {
        $table.printstd();
    };
}

macro_rules! cs_greenln {
    ($($arg:tt)*) => {
        colour::unnamed::write(Some(colour::unnamed::Colour::Green), &format!($($arg)*), true);
    };
}

macro_rules! cs_egreenln {
    ($($arg:tt)*) => {
        unsafe {
            if !$crate::write::WRITER.quiet {
                colour::unnamed::ewrite(Some(colour::unnamed::Colour::Green), &format!($($arg)*), true);
            }
        }
    };
}

macro_rules! cs_eyellowln {
    ($($arg:tt)*) => {
        unsafe {
            if !$crate::write::WRITER.quiet {
                colour::unnamed::ewrite(Some(colour::unnamed::Colour::Yellow), &format!($($arg)*), true);
            }
        }
    };
}

macro_rules! cs_eredln {
    ($($arg:tt)*) => {
        unsafe {
            if !$crate::write::WRITER.quiet {
                colour::unnamed::ewrite(Some(colour::unnamed::Colour::Red), &format!($($arg)*), true);
            }
        }
    };
}
