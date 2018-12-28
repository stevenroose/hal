use clap;

mod decode;
mod encode;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	clap::SubCommand::with_name("tx")
		.about("manipulate transactions")
		.setting(clap::AppSettings::SubcommandRequiredElseHelp)
		.setting(clap::AppSettings::DisableHelpSubcommand)
		.subcommand(decode::subcommand())
		.subcommand(encode::subcommand())
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	match matches.subcommand() {
		("decode", Some(ref m)) => decode::execute(&m),
		("encode", Some(ref m)) => encode::execute(&m),
		(c, _) => println!("command {} unknown", c),
	};
}
