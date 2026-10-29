use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Write;
use std::process::ExitCode;

const USAGE: &str = "\
Loads secrets from Infisical, checks them, then starts your command.

Usage:
  inshape [--optional] --allowlist FILE -- CMD [ARGS...]
  inshape --version
  inshape --help

  --allowlist FILE  names the secrets CMD may use, one per line
  --optional        if Infisical is not configured, start CMD without it
";

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if args.len() == 1 {
        match args[0].to_str() {
            Some("--version") => {
                println!("inshape {}", inshape::VERSION);
                return ExitCode::SUCCESS;
            }
            Some("--help") => {
                print!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            _ => {}
        }
    }
    let host: BTreeMap<OsString, OsString> = std::env::vars_os().collect();
    let err = inshape::run::run(args, host);
    let _ = writeln!(std::io::stderr(), "inshape: {err}");
    ExitCode::from(u8::try_from(err.exit_code()).unwrap_or(1))
}
