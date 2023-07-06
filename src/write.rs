use std::fs::File;
use std::path::PathBuf;

use anyhow::Result;

pub static mut WRITER: Writer = Writer {
    format: Format::Std,
    output: None,
    path: None,
    quiet: false,
};

#[derive(Default)]
pub enum Format {
    #[default]
    Std,
    Csv,
    Json,
}

pub struct Writer {
    pub format: Format,
    pub output: Option<File>,
    pub path: Option<PathBuf>,
    pub quiet: bool,
}

impl Default for Writer {
    fn default() -> Self {
        Self {
            format: Format::Std,
            output: None,
            path: None,
            quiet: false,
        }
    }
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

#[macro_export]
macro_rules! cs_print {
    ($($arg:tt)*) => ({
        use std::io::Write;
        unsafe {
            match $crate::WRITER.output.as_ref() {
                Some(mut f) => {
                    f.write_all(format!($($arg)*).as_bytes()).expect("could not write to file");
                }
                None => {
                    print!($($arg)*);
                }
            }
        }
    })
}

#[macro_export]
macro_rules! cs_println {
    () => {
        use std::io::Write;
        unsafe {
            match $crate::WRITER.output.as_ref() {
                Some(mut f) => {
                    f.write_all(b"\n").expect("could not write to file");
                }
                None => {
                    println!();
                }
            }
        }
    };
    ($($arg:tt)*) => {
        use std::io::Write;
        unsafe {
            match $crate::WRITER.output.as_ref() {
                Some(mut f) => {
                    f.write_all(format!($($arg)*).as_bytes()).expect("could not write to file");
                    f.write_all(b"\n").expect("could not write to file");
                }
                None => {
                    println!($($arg)*);
                }
            }
        }
    }
}

#[macro_export]
macro_rules! cs_eprintln {
    ($($arg:tt)*) => ({
        unsafe {
            if !$crate::WRITER.quiet {
                eprintln!($($arg)*);
            }
        }
    })
}

#[macro_export]
macro_rules! cs_print_json {
    ($value:expr) => {{
        use std::io::Write;
        unsafe {
            match $crate::WRITER.output.as_ref() {
                Some(mut f) => {
                    ::serde_json::to_writer(f, $value)?;
                    f.flush()
                }
                None => {
                    ::serde_json::to_writer(std::io::stdout(), $value)?;
                    std::io::stdout().flush()
                }
            }
        }
    }};
}

#[macro_export]
macro_rules! cs_print_json_pretty {
    ($value:expr) => {{
        use std::io::Write;
        unsafe {
            match $crate::WRITER.output.as_ref() {
                Some(mut f) => {
                    ::serde_json::to_writer_pretty(f, $value)?;
                    f.flush()
                }
                None => {
                    ::serde_json::to_writer_pretty(std::io::stdout(), $value)?;
                    std::io::stdout().flush()
                }
            }
        }
    }};
}

#[macro_export]
macro_rules! cs_print_yaml {
    ($value:expr) => {{
        use std::io::Write;
        unsafe {
            match $crate::WRITER.output.as_ref() {
                Some(mut f) => {
                    ::serde_yaml::to_writer(f, $value)?;
                    f.write_all(b"\n")?;
                    f.flush()
                }
                None => {
                    ::serde_yaml::to_writer(std::io::stdout(), $value)?;
                    println!();
                    std::io::stdout().flush()
                }
            }
        }
    }};
}

macro_rules! cs_print_table {
    ($table:ident) => {
        unsafe {
            match $crate::WRITER.output.as_ref() {
                Some(mut f) => {
                    let _ = $table.print(&mut f).expect("could not write table to file");
                }
                None => $table.printstd(),
            }
        }
    };
}

macro_rules! cs_greenln {
    ($($arg:tt)*) => {
        use std::io::Write;
        unsafe {
            match $crate::WRITER.output.as_ref() {
                Some(mut f) => {
                    f.write_all(format!($($arg)*).as_bytes()).expect("could not write to file");
                    f.write_all(b"\n").expect("could not write to file");
                }
                None => {
                    let _ = std::io::stderr().lock();
                    crossterm::execute!(
                        std::io::stdout(),
                        crossterm::style::SetForegroundColor(crossterm::style::Color::Green),
                        crossterm::style::Print(format!($($arg)*)),
                        crossterm::style::ResetColor
                    ).expect("failed to write line");
                    println!()
                }
            }
        }
    };
}

#[macro_export]
macro_rules! cs_egreenln {
    ($($arg:tt)*) => {
        unsafe {
            if !$crate::WRITER.quiet {
                let _ = std::io::stderr().lock();
                crossterm::execute!(
                    std::io::stderr(),
                    crossterm::style::SetForegroundColor(crossterm::style::Color::Green),
                    crossterm::style::Print(format!($($arg)*)),
                    crossterm::style::ResetColor
                ).expect("failed to write line");
                eprintln!()
            }
        }
    };
}

#[macro_export]
macro_rules! cs_eyellowln {
    ($($arg:tt)*) => {
        unsafe {
            if !$crate::WRITER.quiet {
                let _ = std::io::stderr().lock();
                crossterm::execute!(
                    std::io::stderr(),
                    crossterm::style::SetForegroundColor(crossterm::style::Color::Yellow),
                    crossterm::style::Print(format!($($arg)*)),
                    crossterm::style::ResetColor
                ).expect("failed to write line");
                eprintln!()
            }
        }
    };
}

#[macro_export]
macro_rules! cs_eredln {
    ($($arg:tt)*) => {
        unsafe {
            if !$crate::WRITER.quiet {
                let _ = std::io::stderr().lock();
                crossterm::execute!(
                    std::io::stderr(),
                    crossterm::style::SetForegroundColor(crossterm::style::Color::Red),
                    crossterm::style::Print(format!($($arg)*)),
                    crossterm::style::ResetColor
                ).expect("failed to write line");
                eprintln!()
            }
        }
    };
}
