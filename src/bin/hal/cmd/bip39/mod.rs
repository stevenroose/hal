use clap;

use cmd;

mod generate;
mod get_seed;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("bip39", "BIP-39 mnemonics")
		.subcommand(generate::subcommand())
		.subcommand(get_seed::subcommand())
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	match matches.subcommand() {
		("generate", Some(ref m)) => generate::execute(&m),
		("get-seed", Some(ref m)) => get_seed::execute(&m),
		(_, _) => unreachable!("clap prints help"),
	};
}

