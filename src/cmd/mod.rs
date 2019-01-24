
pub mod address;
pub mod bip32;
pub mod script;
pub mod tx;


/// Create a new subcommand using the template that sets all the common settings.
pub fn new_subcommand<'a>(name: &'static str) -> clap::App<'a, 'a> {
	clap::SubCommand::with_name(name)
		.setting(clap::AppSettings::SubcommandRequiredElseHelp)
		.setting(clap::AppSettings::AllowExternalSubcommands)
		.setting(clap::AppSettings::DisableHelpSubcommand)
}
