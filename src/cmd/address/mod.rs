use clap;

mod inspect;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	clap::SubCommand::with_name("address")
		.about("work with addresses")
		.setting(clap::AppSettings::SubcommandRequiredElseHelp)
		.setting(clap::AppSettings::DisableHelpSubcommand)
		.subcommand(inspect::subcommand())
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	match matches.subcommand() {
		("inspect", Some(ref m)) => inspect::execute(&m),
		(c, _) => println!("command {} unknown", c),
	};
}
