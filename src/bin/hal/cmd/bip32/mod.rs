use clap;

use cmd;

mod derive;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("bip32", "BIP-32 key derivation").subcommand(derive::subcommand())
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	match matches.subcommand() {
		("derive", Some(ref m)) => derive::execute(&m),
		(_, _) => unreachable!("clap prints help"),
	};
}
