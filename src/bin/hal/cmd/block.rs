use std::io::Write;

use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::{block, Block};

use hal::block::{BlockHeaderInfo, BlockInfo};
use crate::prelude::*;
use crate::cmd::tx::create_transaction;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("block", "manipulate blocks")
		.subcommand(cmd_create())
		.subcommand(cmd_decode())
}

pub fn execute<'a>(args: &clap::ArgMatches<'a>) {
	match args.subcommand() {
		("create", Some(ref m)) => exec_create(&m),
		("decode", Some(ref m)) => exec_decode(&m),
		(_, _) => unreachable!("clap prints help"),
	};
}

fn cmd_create<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("create", "create a raw block from JSON")
		.args(&[
			args::arg("block-info", "the block info in JSON").required(false),
			args::flag("raw-stdout", "output the raw bytes of the result to stdout")
				.short("r"),
		])
		.long_about(r#"
Create a block from JSON. Use the same format as the `hal block decode` output.

It's possible to pass the JSON string as the first argument or pass it via stdin.

One can chose to pass in transaction info objects like used for `hal tx create` into the
"transactions" field or hexadecimal raw transactions in the "raw_transactions" field.

Example format:
{
	"header": {
		"block_hash": "0000000000000000000b52e5f79972ccb1b42f14bd5097381551ed7bb4f78478",
		"version": 1,
		"previous_block_hash": "00000000000000000011604b6d32a6074720f60aae04edf20396bbaf65e50edc",
		"merkle_root": "b7f360ae3bb1f6ca1935269d8955808c6606ff20af9b98fbc3ddb7de6c9df5c3",
		"time": 12345,
		"bits": 12345,
		"nonce": 12345
	},

	!! only either of these fields should be provided !!
	"transactions": [
		{ ... }
	],
	"raw_transaction": [
		"deadbeef"
	]
}"#
	)
}

fn create_block_header(info: BlockHeaderInfo) -> block::Header {
	if info.block_hash.is_some() {
		warn!("Field \"block_hash\" is ignored.");
	}

	block::Header {
		version: block::Version::from_consensus(info.version),
		prev_blockhash: info.previous_block_hash,
		merkle_root: info.merkle_root,
		time: info.time,
		bits: bitcoin::pow::CompactTarget::from_consensus(info.bits),
		nonce: info.nonce,
	}
}

fn exec_create<'a>(args: &clap::ArgMatches<'a>) {
	let info = serde_json::from_str::<BlockInfo>(&util::arg_or_stdin(args, "block-info"))
		.need("invaid json JSON input");

	if info.txids.is_some() {
		warn!("Field \"txids\" is ignored.");
	}

	let mut used_network = cmd::tx::UsedNetwork::new(args.explicit_network());
	let block = Block {
		header: create_block_header(info.header),
		txdata: match (info.transactions, info.raw_transactions) {
			(Some(_), Some(_)) => exit!("Can't provide transactions both in JSON and raw."),
			(None, None) => exit!("No transactions provided."),
			(Some(infos), None) => infos.into_iter().map(|t| {
				create_transaction(t, &mut used_network)
			}).collect(),
			(None, Some(raws)) => raws
				.into_iter()
				.map(|r| deserialize(&r.0).need("invalid raw transaction"))
				.collect(),
		},
	};

	let block_bytes = serialize(&block);
	if args.is_present("raw-stdout") {
		::std::io::stdout().write_all(&block_bytes).unwrap();
	} else {
		print!("{}", hex::encode(&block_bytes));
	}
}

fn cmd_decode<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("decode", "decode a raw block to JSON")
		.arg(args::arg("raw-block", "the raw block in hex").required(false))
		.arg(args::flag("txids", "provide transactions IDs instead of full transactions"))
}

fn exec_decode<'a>(args: &clap::ArgMatches<'a>) {
	let hex_tx = util::arg_or_stdin(args, "raw-block");
	let raw_tx = hex::decode(hex_tx.as_ref()).need("could not decode raw block hex");

	if args.is_present("txids") {
		let block: Block = deserialize(&raw_tx).need("invalid block format");
		let info = hal::block::BlockInfo {
			header: hal::GetInfo::get_info(&block.header, args.network()),
			bip34_block_height: block.bip34_block_height().ok(),
			txids: Some(block.txdata.iter().map(|t| t.compute_txid()).collect()),
			transactions: None,
			raw_transactions: None,
		};
		args.print_output(&info)
	} else {
		let block: Block = match deserialize(&raw_tx) {
			Ok(block) => block,
			Err(_) => {
				let header = deserialize::<block::Header>(&raw_tx).expect("invalid block format");
				let block = Block {
					header: header,
					txdata: Default::default(),
				};
				block
			},
		};
		let info = hal::GetInfo::get_info(&block, args.network());
		args.print_output(&info)
	}
}
