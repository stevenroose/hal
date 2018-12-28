use bitcoin::consensus;
use clap;

use hal;

use bitcoin::Transaction;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	clap::SubCommand::with_name("decode")
		.about("decode a raw transaction to JSON")
		.arg(
			clap::Arg::with_name("raw-tx")
				.help("the raw transaction in hex")
				.takes_value(true)
				.required(true),
		)
		.arg(
			// This influences the addresses we print.
			clap::Arg::with_name("testnet")
				.long("testnet")
				.help("for testnet transaction")
				.takes_value(true)
				.required(false),
		)
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	let hex_tx = matches.value_of("raw-tx").expect("no raw tx provided");
	let raw_tx = hex::decode(hex_tx).expect("could not decode raw tx");
	let tx: Transaction = consensus::encode::deserialize(&raw_tx).expect("invalid tx format");

	let info = hal::TransactionInfo::create(&tx, matches.is_present("testnet"));
	serde_json::to_writer_pretty(::std::io::stdout(), &info).unwrap();
}
