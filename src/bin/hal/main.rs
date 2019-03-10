extern crate bitcoin;
extern crate bitcoin_bech32;
extern crate bitcoin_hashes;
extern crate lightning_invoice;
#[macro_use]
extern crate log;
extern crate base64;
extern crate clap;
extern crate fern;
extern crate hex;
extern crate jobserver;
extern crate secp256k1;
extern crate serde_json;
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
		.version("0.0.0")
		.author("Steven Roose <steven@stevenroose.org>")
		.about("hal - the Bitcoin companion")
		.setting(clap::AppSettings::GlobalVersion)
		.setting(clap::AppSettings::VersionlessSubcommands)
		.setting(clap::AppSettings::AllowExternalSubcommands)
		//TODO(stevenroose) re-enable after https://github.com/clap-rs/clap/pull/1412/
		//.setting(clap::AppSettings::SubcommandRequiredElseHelp)
		.setting(clap::AppSettings::DisableHelpSubcommand)
		.setting(clap::AppSettings::AllArgsOverrideSelf)
		.help_message("print help information")
		.version_message("print version information")
		.subcommands(cmd::subcommands())
		.arg(
			cmd::opt("verbose", "print verbose logging output to stderr")
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
	panic::set_hook(Box::new(|info| {
		let message = if let Some(m) = info.payload().downcast_ref::<String>() {
			m
		} else if let Some(m) = info.payload().downcast_ref::<&str>() {
			m
		} else {
			"No error message provided"
		};
		println!("Execution failed: {}", message);
		process::exit(1);
	}));

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
		("bip32", Some(ref m)) => cmd::bip32::execute(&m),
		("ln", Some(ref m)) => cmd::ln::execute(&m),
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
