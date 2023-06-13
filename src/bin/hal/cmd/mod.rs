pub mod address;
pub mod bech32;
pub mod bip32;
pub mod bip39;
pub mod block;
pub mod key;
pub mod ln;
pub mod message;
pub mod miniscript;
pub mod psbt;
pub mod script;
pub mod tx;

use bitcoin::Network;

/// Build a list of all built-in subcommands.
pub fn subcommands() -> Vec<clap::App<'static, 'static>> {
	vec![
		address::subcommand(),
		bech32::subcommand(),
		block::subcommand(),
		key::subcommand(),
		ln::subcommand(),
		message::subcommand(),
		miniscript::subcommand(),
		tx::subcommand(),
		psbt::subcommand(),
		script::subcommand(),
		bip32::subcommand(),
		bip39::subcommand(),
	]
}

/// Construct a new command option.
pub fn opt<'a>(name: &'a str, help: &'a str) -> clap::Arg<'a, 'a> {
	clap::Arg::with_name(name).long(name).help(help)
}

/// Construct a new positional argument.
pub fn arg<'a>(name: &'a str, help: &'a str) -> clap::Arg<'a, 'a> {
	clap::Arg::with_name(name).help(help).takes_value(true)
}

/// Create a new subcommand group using the template that sets all the common settings.
/// This is not intended for actual commands, but for subcommands that host a bunch of other
/// subcommands.
pub fn subcommand_group<'a>(name: &'a str, about: &'a str) -> clap::App<'a, 'a> {
	clap::SubCommand::with_name(name).about(about).settings(&[
		clap::AppSettings::SubcommandRequiredElseHelp,
		clap::AppSettings::DisableHelpSubcommand,
		clap::AppSettings::VersionlessSubcommands,
		clap::AppSettings::UnifiedHelpMessage,
	])
}

/// Create a new subcommand using the template that sets all the common settings.
pub fn subcommand<'a>(name: &'a str, about: &'a str) -> clap::App<'a, 'a> {
	clap::SubCommand::with_name(name)
		.about(about)
		.setting(clap::AppSettings::DisableHelpSubcommand)
}

pub fn opts_networks() -> Vec<clap::Arg<'static, 'static>> {
	vec![
		clap::Arg::with_name("testnet")
			.long("testnet")
			.short("t")
			.help("run in testnet mode")
			.takes_value(false)
			.required(false),
		clap::Arg::with_name("regtest")
			.long("regtest")
			.help("run in regtest mode")
			.takes_value(false)
			.required(false),
	]
}

pub fn network(matches: &clap::ArgMatches) -> Network {
	if matches.is_present("testnet") {
		Network::Testnet
	} else if matches.is_present("regtest") {
		Network::Regtest
	} else {
		Network::Bitcoin
	}
}

pub fn opt_yaml() -> clap::Arg<'static, 'static> {
	clap::Arg::with_name("yaml")
		.long("yaml")
		.short("y")
		.help("print output in YAML instead of JSON")
		.takes_value(false)
		.required(false)
}

pub fn print_output<T: serde::Serialize>(matches: &clap::ArgMatches, out: &T) {
	if matches.is_present("yaml") {
		serde_yaml::to_writer(::std::io::stdout(), &out).unwrap();
	} else {
		serde_json::to_writer_pretty(::std::io::stdout(), &out).unwrap();
	}
}
