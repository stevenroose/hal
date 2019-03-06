use clap;

use bitcoin::consensus::deserialize;
use bitcoin::util::psbt;

use cmd;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	clap::SubCommand::with_name("decode")
		.about("decode a PSBT to JSON")
		.args(&cmd::args_networks())
		.arg(cmd::arg_yaml())
		.arg(
			clap::Arg::with_name("psbt")
				.help("the PSBT file or raw PSBT in hex")
				.takes_value(true)
				.required(true),
		)
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	let (raw_psbt, _) = super::file_or_raw(matches.value_of("psbt").unwrap());

	let psbt: psbt::PartiallySignedTransaction = deserialize(&raw_psbt).expect("invalid PSBT");

	let info = hal::GetInfo::get_info(&psbt, cmd::network(matches));
	cmd::print_output(matches, &info)
}
