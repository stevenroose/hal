use clap;

use cmd;

mod derive;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::new_subcommand("bip32")
		.about("BIP-32 key derivation")
		.subcommand(derive::subcommand())
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	match matches.subcommand() {
		("derive", Some(ref m)) => derive::execute(&m),
		(_, _) => unreachable!("clap prints help"),
	};
}
