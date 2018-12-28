use clap;

mod derive;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	clap::SubCommand::with_name("bip32")
		.about("BIP-32 key derivation")
		.setting(clap::AppSettings::SubcommandRequiredElseHelp)
		.setting(clap::AppSettings::DisableHelpSubcommand)
		.subcommand(derive::subcommand())
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	match matches.subcommand() {
		("derive", Some(ref m)) => derive::execute(&m),
		(c, _) => println!("command {} unknown", c),
	};
}
