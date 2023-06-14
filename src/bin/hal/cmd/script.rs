use bitcoin::Script;
use clap;
use hex;

use crate::prelude::*;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("script", "manipulate scripts").subcommand(cmd_decode())
}

pub fn execute<'a>(args: &clap::ArgMatches<'a>) {
	match args.subcommand() {
		("decode", Some(ref m)) => exec_decode(&m),
		(_, _) => unreachable!("clap prints help"),
	};
}

fn cmd_decode<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("decode", "decode hex script")
		.arg(args::arg("hex-script", "script in hex").required(true))
}

fn exec_decode<'a>(args: &clap::ArgMatches<'a>) {
	let hex_script = args.value_of("hex-script").need("no script provided");
	let raw_script = hex::decode(hex_script).need("could not decode raw script");
	let script: Script = raw_script.into();

	print!("{}", script.asm());
}
