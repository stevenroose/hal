use clap;

use cmd;

mod inspect;
mod create;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::new_subcommand("address")
		.about("work with addresses")
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
