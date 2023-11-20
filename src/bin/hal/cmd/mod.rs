pub mod address;
pub mod bech32;
pub mod bip32;
pub mod bip39;
pub mod block;
pub mod hash;
pub mod key;
pub mod ln;
pub mod merkle;
pub mod message;
pub mod miniscript;
pub mod musig;
pub mod psbt;
pub mod random;
pub mod script;
pub mod tx;

/// Build a list of all built-in subcommands.
pub fn subcommands() -> Vec<clap::App<'static, 'static>> {
	vec![
		address::subcommand(),
		bech32::subcommand(),
		bip32::subcommand(),
		bip39::subcommand(),
		block::subcommand(),
		hash::subcommand(),
		key::subcommand(),
		ln::subcommand(),
		merkle::subcommand(),
		message::subcommand(),
		miniscript::subcommand(),
		musig::subcommand(),
		psbt::subcommand(),
		random::subcommand(),
		script::subcommand(),
		tx::subcommand(),
	]
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
