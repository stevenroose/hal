pub mod address;
pub mod bip32;
pub mod script;
pub mod tx;

use bitcoin::Network;

/// Create a new subcommand using the template that sets all the common settings.
pub fn new_subcommand<'a>(name: &'static str) -> clap::App<'a, 'a> {
	clap::SubCommand::with_name(name)
		.setting(clap::AppSettings::SubcommandRequiredElseHelp)
		.setting(clap::AppSettings::AllowExternalSubcommands)
		.setting(clap::AppSettings::DisableHelpSubcommand)
}

pub fn arg_testnet<'a>() -> clap::Arg<'a, 'a> {
	clap::Arg::with_name("testnet")
		.long("testnet")
		.short("t")
		.help("run in testnet mode")
		.takes_value(false)
		.required(false)
}

pub fn network<'a>(matches: &clap::ArgMatches<'a>) -> Network {
	if matches.is_present("testnet") {
		Network::Testnet
	} else {
		Network::Bitcoin
	}
}

pub fn arg_yaml<'a>() -> clap::Arg<'a, 'a> {
	clap::Arg::with_name("yaml")
		.long("yaml")
		.short("y")
		.help("print output in YAML instead of JSON")
		.takes_value(false)
		.required(false)
}

pub fn print_output<'a, T: serde::Serialize>(matches: &clap::ArgMatches<'a>, out: &T) {
	if matches.is_present("yaml") {
		serde_yaml::to_writer(::std::io::stdout(), &out).unwrap();
	} else {
		serde_json::to_writer_pretty(::std::io::stdout(), &out).unwrap();
	}
}
