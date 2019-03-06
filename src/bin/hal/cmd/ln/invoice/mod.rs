use clap;

use cmd;

mod decode;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::new_subcommand("invoice")
		.about("handle Lightning invoices")
		.subcommand(decode::subcommand())
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	match matches.subcommand() {
		("decode", Some(ref m)) => decode::execute(&m),
		(_, _) => unreachable!("clap prints help"),
	};
}
