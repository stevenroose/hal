use clap;

use cmd;

mod create;
mod inspect;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("address", "work with addresses")
		.subcommand(create::subcommand())
		.subcommand(inspect::subcommand())
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	match matches.subcommand() {
		("create", Some(ref m)) => create::execute(&m),
		("inspect", Some(ref m)) => inspect::execute(&m),
		(_, _) => unreachable!("clap prints help"),
	};
}
