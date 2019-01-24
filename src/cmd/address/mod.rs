use clap;

use cmd;

mod inspect;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::new_subcommand("address")
		.about("work with addresses")
		.subcommand(inspect::subcommand())
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	match matches.subcommand() {
		("inspect", Some(ref m)) => inspect::execute(&m),
		(_, _) => unreachable!("clap prints help"),
	};
}
