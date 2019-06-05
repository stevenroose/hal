use clap;

use cmd;

mod derive;
mod inspect;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("bip32", "BIP-32 key derivation")
		.subcommand(derive::subcommand())
		.subcommand(inspect::subcommand())
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	match matches.subcommand() {
		("derive", Some(ref m)) => derive::execute(&m),
		("inspect", Some(ref m)) => inspect::execute(&m),
		(_, _) => unreachable!("clap prints help"),
	};
}
