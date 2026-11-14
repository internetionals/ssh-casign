use clap::Parser;
use std::ffi::OsString;

pub(crate) mod agent;
pub(crate) mod auth;
pub(crate) mod cmd;
pub(crate) mod config;
pub(crate) mod discovery;
pub mod error;
pub(crate) mod sign;

pub fn run<I, T>(args: I) -> cmd::CmdResult
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let args = cmd::Args::try_parse_from(args)?;
    cmd::run(&args)
}
