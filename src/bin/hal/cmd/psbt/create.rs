use std::fs::File;
use std::io::Write;

use base64;
use clap;
use hex;

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::util::psbt;
use bitcoin::Transaction;

use cmd;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("create", "create a PSBT from an unsigned raw transaction").args(&[
		cmd::arg("raw-tx", "the raw transaction in hex").required(true),
		cmd::opt("output", "where to save the merged PSBT output")
			.short("o")
			.takes_value(true)
			.required(false),
		cmd::opt("raw-stdout", "output the raw bytes of the result to stdout")
			.short("r")
			.required(false),
	])
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	let hex_tx = matches.value_of("raw-tx").expect("no raw tx provided");
	let raw_tx = hex::decode(hex_tx).expect("could not decode raw tx");
	let tx: Transaction = deserialize(&raw_tx).expect("invalid tx format");

	let psbt = psbt::PartiallySignedTransaction::from_unsigned_tx(tx)
		.expect("couldn't create a PSBT from the transaction");

	let serialized = serialize(&psbt);
	if let Some(path) = matches.value_of("output") {
		let mut file = File::create(&path).expect("failed to open output file");
		file.write_all(&serialized).expect("error writing output file");
	} else if matches.is_present("raw-stdout") {
		::std::io::stdout().write_all(&serialized).unwrap();
	} else {
		print!("{}", base64::encode(&serialized));
	}
}
