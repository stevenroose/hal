use clap;

use cmd;

mod decode;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::new_subcommand("script").about("manipulate scripts").subcommand(decode::subcommand())
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	match matches.subcommand() {
		("decode", Some(ref m)) => decode::execute(&m),
		(_, _) => unreachable!("clap prints help"),
	};
}
