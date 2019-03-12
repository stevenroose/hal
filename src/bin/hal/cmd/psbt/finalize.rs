use std::io::Write;

use clap;

use bitcoin::consensus::deserialize;
use bitcoin::consensus::serialize;
use bitcoin::util::psbt;

use cmd;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("fimalize", "finalize a PSBT and print the fully signed tx in hex").args(&[
		cmd::arg("psbt", "PSBT to finalize, either base64/hex or a file path").required(true),
		cmd::opt("raw-stdout", "output the raw bytes of the result to stdout")
			.short("r")
			.required(false),
	])
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	let (raw, _) = super::file_or_raw(&matches.value_of("psbt").unwrap());
	let psbt: psbt::PartiallySignedTransaction = deserialize(&raw).expect("invalid PSBT format");

	if psbt.inputs.iter().any(|i| i.final_script_sig.is_none() && i.final_script_witness.is_none())
	{
		panic!("PSBT is missing input data!");
	}

	let finalized_raw = serialize(&psbt.extract_tx());
	if matches.is_present("raw-stdout") {
		::std::io::stdout().write_all(&finalized_raw).unwrap();
	} else {
		print!("{}", ::hex::encode(&finalized_raw));
	}
}
