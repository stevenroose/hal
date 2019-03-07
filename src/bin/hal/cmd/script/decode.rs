use bitcoin::Script;
use clap;
use hex;

use cmd;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("decode", "decode hex script")
		.arg(cmd::opt("hex-script", "script in hex").takes_value(true).required(true))
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	let hex_script = matches.value_of("hex-script").expect("no script provided");
	let raw_script = hex::decode(hex_script).expect("could not decode raw script");
	let script: Script = raw_script.into();

	println!("{}", script); //TODO(stevenroose) asm
}
