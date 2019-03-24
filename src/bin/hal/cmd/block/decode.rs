use bitcoin::consensus::encode::deserialize;
use bitcoin::Block;
use clap;

use cmd;
use hal;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("decode", "decode a raw block to JSON").args(&cmd::opts_networks()).args(&[
		cmd::opt_yaml(),
		cmd::arg("raw-block", "the raw block in hex").required(true),
		cmd::opt("txids", "provide transactions IDs instead of full transactions"),
	])
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	let hex_tx = matches.value_of("raw-block").expect("no raw block provided");
	let raw_tx = hex::decode(hex_tx).expect("could not decode raw block hex");
	let block: Block = deserialize(&raw_tx).expect("invalid block format");

	if matches.is_present("txids") {
		let info = hal::block::BlockInfo {
			header: hal::GetInfo::get_info(&block.header, cmd::network(matches)),
			txids: Some(block.txdata.iter().map(|t| t.txid()).collect()),
			transactions: None,
			raw_transactions: None,
		};
		cmd::print_output(matches, &info)
	} else {
		let info = hal::GetInfo::get_info(&block, cmd::network(matches));
		cmd::print_output(matches, &info)
	}
}
