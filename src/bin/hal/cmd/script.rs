use bitcoin::Script;
use clap;
use hex;

use crate::cmd;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("script", "manipulate scripts").subcommand(cmd_decode())
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	match matches.subcommand() {
		("decode", Some(ref m)) => exec_decode(&m),
		(_, _) => unreachable!("clap prints help"),
	};
}

fn cmd_decode<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("decode", "decode hex script")
		.arg(cmd::arg("hex-script", "script in hex").required(true))
}

fn exec_decode<'a>(matches: &clap::ArgMatches<'a>) {
	let hex_script = matches.value_of("hex-script").expect("no script provided");
	let raw_script = hex::decode(hex_script).expect("could not decode raw script");
	let script: Script = raw_script.into();

	print!("{}", script.asm());
}
