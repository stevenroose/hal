use clap;

use cmd;

mod invoice;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("ln", "everything Lightning").subcommand(invoice::subcommand())
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	match matches.subcommand() {
		("invoice", Some(ref m)) => invoice::execute(&m),
		(_, _) => unreachable!("clap prints help"),
	};
}
