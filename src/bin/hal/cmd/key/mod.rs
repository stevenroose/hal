use clap;

use cmd;

mod generate;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("key", "work with private and public keys")
		.subcommand(generate::subcommand())
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	match matches.subcommand() {
		("generate", Some(ref m)) => generate::execute(&m),
		(_, _) => unreachable!("clap prints help"),
	};
}
