use clap;

use bitcoin::consensus::deserialize;
use bitcoin::util::psbt;

use cmd;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("decode", "decode a PSBT to JSON").args(&cmd::opts_networks()).args(&[
		cmd::opt_yaml(),
		cmd::arg("psbt", "the PSBT file or raw PSBT in base64/hex").required(true),
	])
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	let (raw_psbt, _) = super::file_or_raw(matches.value_of("psbt").unwrap());

	let psbt: psbt::PartiallySignedTransaction = deserialize(&raw_psbt).expect("invalid PSBT");

	let info = hal::GetInfo::get_info(&psbt, cmd::network(matches));
	cmd::print_output(matches, &info)
}
