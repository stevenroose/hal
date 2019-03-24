use clap;

use cmd;

mod create;
mod decode;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("block", "manipulate blocks")
		.subcommand(create::subcommand())
		.subcommand(decode::subcommand())
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	match matches.subcommand() {
		("create", Some(ref m)) => create::execute(&m),
		("decode", Some(ref m)) => decode::execute(&m),
		(_, _) => unreachable!("clap prints help"),
	};
}
