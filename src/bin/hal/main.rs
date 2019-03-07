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
extern crate secp256k1;
extern crate serde_json;

extern crate hal;

use std::panic;
use std::process;

pub mod cmd;

fn setup_logger(lvl: log::LevelFilter) {
	fern::Dispatch::new()
		.format(|out, message, _record| out.finish(format_args!("{}", message)))
		.level(lvl)
		.chain(std::io::stderr())
		.apply()
		.expect("error setting up logger");
}

fn init_app<'a, 'b>() -> clap::App<'a, 'b> {
	clap::App::new("hal")
		.version("0.0.0")
		.author("Steven Roose <steven@stevenroose.org>")
		.about("hal - the Bitcoin companion")
		.setting(clap::AppSettings::GlobalVersion)
		.setting(clap::AppSettings::VersionlessSubcommands)
		.setting(clap::AppSettings::SubcommandRequiredElseHelp)
		.setting(clap::AppSettings::AllowExternalSubcommands)
		.setting(clap::AppSettings::DisableHelpSubcommand)
		.setting(clap::AppSettings::AllArgsOverrideSelf)
		.subcommands(cmd::subcommands())
		.arg(
			cmd::opt("verbose", "print verbose logging output to stderr")
				.short("v")
				.takes_value(false)
				.global(true),
		)
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

	let app = init_app();
	let matches = app.get_matches();

	// Enable logging in verbose mode.
	match matches.is_present("verbose") {
		true => setup_logger(log::LevelFilter::Trace),
		false => setup_logger(log::LevelFilter::Warn),
	}

	// Execute commands.
	match matches.subcommand() {
		("address", Some(ref m)) => cmd::address::execute(&m),
		("bip32", Some(ref m)) => cmd::bip32::execute(&m),
		("ln", Some(ref m)) => cmd::ln::execute(&m),
		("psbt", Some(ref m)) => cmd::psbt::execute(&m),
		("script", Some(ref m)) => cmd::script::execute(&m),
		("tx", Some(ref m)) => cmd::tx::execute(&m),
		(c, _) => println!("command {} unknown", c),
	};
}
