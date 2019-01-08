use clap;

mod decode;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	clap::SubCommand::with_name("script")
		.about("manipulate scripts")
		.setting(clap::AppSettings::SubcommandRequiredElseHelp)
		.setting(clap::AppSettings::DisableHelpSubcommand)
		.subcommand(decode::subcommand())
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	println!("tx");
	match matches.subcommand() {
		("decode", Some(ref m)) => decode::execute(&m),
		(c, _) => println!("command {} unknown", c),
	};
}
