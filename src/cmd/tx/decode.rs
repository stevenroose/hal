use bitcoin::consensus::encode::deserialize;
use bitcoin::Transaction;
use clap;

use hal;
use cmd;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	clap::SubCommand::with_name("decode")
		.about("decode a raw transaction to JSON")
		.arg(cmd::arg_testnet())
		.arg(cmd::arg_yaml())
		.arg(
			clap::Arg::with_name("raw-tx")
				.help("the raw transaction in hex")
				.takes_value(true)
				.required(true),
		)
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	let hex_tx = matches.value_of("raw-tx").expect("no raw tx provided");
	let raw_tx = hex::decode(hex_tx).expect("could not decode raw tx");
	let tx: Transaction = deserialize(&raw_tx).expect("invalid tx format");

	let info = hal::GetInfo::get_info(&tx, cmd::network(matches));
	cmd::print_output(matches, &info)
}
