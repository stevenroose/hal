extern crate bip39;
extern crate bitcoin;
extern crate lightning_invoice;
#[macro_use]
extern crate log;
extern crate miniscript;
extern crate base64;
extern crate clap;
extern crate fern;
extern crate hex;
extern crate jobserver;
extern crate rand;
extern crate serde_json;
extern crate secp256k1;
extern crate shell_escape;

extern crate hal;

use std::env;
use std::io::{self, Write};
use std::panic;
use std::process;

pub mod cmd;
mod process_builder;
pub mod util;

/// Setup logging with the given log level.
fn setup_logger(lvl: log::LevelFilter) {
	fern::Dispatch::new()
		.format(|out, message, _record| out.finish(format_args!("{}", message)))
		.level(lvl)
		.chain(std::io::stderr())
		.apply()
		.expect("error setting up logger");
}

/// Create the main app object.
fn init_app<'a, 'b>() -> clap::App<'a, 'b> {
	clap::App::new("hal")
		.version(clap::crate_version!())
		.author("Steven Roose <steven@stevenroose.org>")
		.about("hal - the Bitcoin companion")
		.settings(&[
			clap::AppSettings::GlobalVersion,
			clap::AppSettings::UnifiedHelpMessage,
			clap::AppSettings::VersionlessSubcommands,
			clap::AppSettings::AllowExternalSubcommands,
			clap::AppSettings::DisableHelpSubcommand,
			clap::AppSettings::AllArgsOverrideSelf,
			//TODO(stevenroose) re-enable after https://github.com/clap-rs/clap/pull/1412/
			//clap::AppSettings::SubcommandRequiredElseHelp,
		])
		.subcommands(cmd::subcommands())
		.arg(
			cmd::opt("verbose", "Print verbose logging output to stderr")
				.short("v")
				.takes_value(false)
				.global(true),
		)
}

/// The help appendix listing external subcommands.
fn external_help() -> String {
	let mut cmds: Vec<String> = util::list_commands()
		.into_iter()
		.filter_map(|c| match c {
			util::CommandInfo::External {
				name,
				path: _,
			} => Some(name),
			_ => None,
		})
		.collect();
	cmds.sort();

	"EXTERNAL SUBCOMMANDS:\n    ".to_owned() + &cmds.join("\n    ")
}

fn main() {
	// Apply a custom panic hook to print a more user-friendly message
	// in case the execution fails.
	// We skip this for people that are interested in the panic message.
	if env::var("RUST_BACKTRACE").unwrap_or(String::new()) != "1" {
		panic::set_hook(Box::new(|info| {
			let message = if let Some(m) = info.payload().downcast_ref::<String>() {
				m
			} else if let Some(m) = info.payload().downcast_ref::<&str>() {
				m
			} else {
				"No error message provided"
			};
			eprintln!("Execution failed: {}", message);
			process::exit(1);
		}));
	}

	let external_help = external_help();
	let app = init_app().after_help(external_help.as_str());
	let matches = app.clone().get_matches();

	// Enable logging in verbose mode.
	match matches.is_present("verbose") {
		true => setup_logger(log::LevelFilter::Trace),
		false => setup_logger(log::LevelFilter::Warn),
	}

	match matches.subcommand() {
		("", _) => {
			app.write_help(&mut io::stderr()).unwrap();
			io::stderr().write(b"\n").unwrap();
			process::exit(1);
		}
		("address", Some(ref m)) => cmd::address::execute(&m),
		("bech32", Some(ref m)) => cmd::bech32::execute(&m),
		("block", Some(ref m)) => cmd::block::execute(&m),
		("bip32", Some(ref m)) => cmd::bip32::execute(&m),
		("bip39", Some(ref m)) => cmd::bip39::execute(&m),
		("key", Some(ref m)) => cmd::key::execute(&m),
		("ln", Some(ref m)) => cmd::ln::execute(&m),
		("message", Some(ref m)) => cmd::message::execute(&m),
		("miniscript", Some(ref m)) => cmd::miniscript::execute(&m),
		("psbt", Some(ref m)) => cmd::psbt::execute(&m),
		("script", Some(ref m)) => cmd::script::execute(&m),
		("tx", Some(ref m)) => cmd::tx::execute(&m),
		(cmd, subcommand_args) => {
			// Try execute an external subcommand.

			let command_exe = format!("hal-{}{}", cmd, env::consts::EXE_SUFFIX);
			let path = util::search_directories()
				.iter()
				.map(|dir| dir.join(&command_exe))
				.find(|file| util::is_executable(file));
			let command = match path {
				Some(command) => command,
				None => {
					if let Some(closest) = util::find_closest(cmd) {
						panic!("no such subcommand: `{}`\n\n\tDid you mean `{}`?\n", cmd, closest);
					}
					panic!("no such subcommand: `{}`", cmd);
				}
			};

			let mut ext_args: Vec<&str> = vec![cmd];
			if let Some(args) = subcommand_args {
				ext_args.extend(args.values_of("").unwrap_or_default());
			}

			info!("Delegating to external executable '{}'", command.as_path().display());
			process_builder::process(&command).args(&ext_args).exec_replace();
		}
	}
}
