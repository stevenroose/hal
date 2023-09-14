use std::collections::HashSet;
use std::io::Write;
use std::str::FromStr;
use std::process;

use bitcoin::merkle_tree::PartialMerkleTree;
use bitcoin::{Block, Txid};

use clap;

use crate::prelude::*;


pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("merkle", "tool for merkle tree and proof creation")
		.subcommand(cmd_proof_create())
		.subcommand(cmd_proof_check())
}

pub fn execute<'a>(args: &clap::ArgMatches<'a>) {
	match args.subcommand() {
		("proof-create", Some(ref m)) => exec_proof_create(&m),
		("proof-check", Some(ref m)) => exec_proof_check(&m),
		(_, _) => unreachable!("clap prints help"),
	};
}

fn cmd_proof_create<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("proof-create", "create a merkle inclusion proof")
		.arg(args::opt("block", "the full block in hex"))
		.arg(args::opt("block-txids", "all txids in the block, separated by a comma"))
		.arg(args::opt("txid", "the txids to proof inclusion for").required(true))
		.arg(args::opt("raw-stdout", "output the raw bytes of the result to stdout")
			.short("r")
			.required(false))
}

fn exec_proof_create<'a>(args: &clap::ArgMatches<'a>) {
	let block_txids: Vec<Txid> = {
		if let Some(block_res) = args.hex_consensus::<Block>("block") {
			let block = block_res.need("invalid block");
			block.txdata.iter().map(|tx| tx.txid()).collect()
		} else if let Some(txids) = args.value_of("block-txid") {
			txids.split(",").map(|s| Txid::from_str(s).need("invalid block txid")).collect()
		} else {
			exit!("Need to provide either --block or --block-txids");
		}
	};

	let txids = args.values_of("txid").need("at least one txid should be provided")
		.map(|s| Txid::from_str(s).need("invalid txid"))
		.collect::<HashSet<_>>();

	let included = block_txids.iter().map(|txid| txids.contains(txid)).collect::<Vec<_>>();

	let proof = PartialMerkleTree::from_txids(&block_txids, &included);
	let proof_bytes = bitcoin::consensus::serialize(&proof);

	if args.is_present("raw-stdout") {
		::std::io::stdout().write_all(&proof_bytes).unwrap();
	} else {
		print!("{}", hex::encode(&proof_bytes));
	}
}

fn cmd_proof_check<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("proof-check", "check for txids in the proof; \
					if no txids are provided, it prints all of the included ones")
		.arg(args::arg("proof", "merkle proof in hex").required(true))
		.arg(args::opt("txid", "the txids to proof inclusion for"))
		.arg(args::opt("indices", "also print the indices for the txids"))
}

fn exec_proof_check<'a>(args: &clap::ArgMatches<'a>) {
	let proof = args.hex_consensus::<PartialMerkleTree>("proof")
		.need("no proof provided")
		.need("invalid proof format");

	let mut txids = Vec::new();
	let mut idxs = Vec::new();
	//TODO(stevenroose) make this into a need() when we update bitcoin dep
	proof.extract_matches(&mut txids, &mut idxs).expect("invalid proof");

	if let Some(check_txids) = args.values_of("txid") {
		let mut ok = true;
		for check_txid in check_txids.map(|s| Txid::from_str(s).need("invalid txid")) {
			if !txids.contains(&check_txid) {
				eprintln!("Txid {} is not included", check_txid);
				ok = false;
			}
		}

		if ok {
			eprintln!("All txids are included");
		} else {
			process::exit(1);
		}
	} else {
		for (txid, idx) in txids.iter().zip(idxs.iter()) {
			if args.is_present("indices") {
				println!("{} {}", txid, idx);
			} else {
				println!("{}", txid);
			}
		}
	}
}
