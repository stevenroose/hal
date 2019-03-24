use std::io::Write;

use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::{Block, BlockHeader};

use cmd;
use cmd::tx::create::create_transaction;
use hal::block::{BlockHeaderInfo, BlockInfo};

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("create", "create a raw block from JSON").args(&[
		cmd::arg("block-info", "the block info in JSON").required(true),
		cmd::opt("raw-stdout", "output the raw bytes of the result to stdout")
			.short("r")
			.required(false),
	])
}

fn create_block_header(info: BlockHeaderInfo) -> BlockHeader {
	if info.block_hash.is_some() {
		warn!("Field \"block_hash\" is ignored.");
	}

	BlockHeader {
		version: info.version,
		prev_blockhash: info.previous_block_hash,
		merkle_root: info.merkle_root,
		time: info.time,
		bits: info.bits,
		nonce: info.nonce,
	}
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	let json_block = matches.value_of("block-info").expect("no JSON blok info provided");
	let info: BlockInfo = serde_json::from_str(json_block).expect("invalid JSON");

	if info.txids.is_some() {
		warn!("Field \"txids\" is ignored.");
	}

	let block = Block {
		header: create_block_header(info.header),
		txdata: match (info.transactions, info.raw_transactions) {
			(Some(_), Some(_)) => panic!("Can't provide transactions both in JSON and raw."),
			(None, None) => panic!("No transactions provided."),
			(Some(infos), None) => infos.into_iter().map(create_transaction).collect(),
			(None, Some(raws)) => raws
				.into_iter()
				.map(|r| deserialize(&r.0).expect("invalid raw transaction"))
				.collect(),
		},
	};

	let block_bytes = serialize(&block);
	if matches.is_present("raw-stdout") {
		::std::io::stdout().write_all(&block_bytes).unwrap();
	} else {
		print!("{}", hex::encode(&block_bytes));
	}
}
