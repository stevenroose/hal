use clap;

use cmd;

mod decode;
// mod encode;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("bech32", "encode and decode the bech32 format")
		// .subcommand(encode::subcommand())
		.subcommand(decode::subcommand())
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	match matches.subcommand() {
		// ("encode", Some(ref m)) => encode::execute(&m),
		("decode", Some(ref m)) => decode::execute(&m),
		(_, _) => unreachable!("clap prints help"),
	};
}
