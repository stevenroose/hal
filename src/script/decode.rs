use bitcoin::Script;
use clap;
use hex;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	clap::SubCommand::with_name("decode")
		.about("decode hex script")
		.arg(
			clap::Arg::with_name("hex-script")
				.help("script in hex")
				.takes_value(true)
				.required(true),
		)
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	let hex_script = matches.value_of("hex-script").expect("no script provided");
	let raw_script = hex::decode(hex_script).expect("could not decode raw script");
	let script: Script = raw_script.into();

	println!("{}", script); //TODO(stevenroose) asm
}
