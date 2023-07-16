use std::io;

use bip39::{Language, Mnemonic};
use bitcoin::hashes::{sha256, Hash};
use clap;
use hex;
use rand::Rng;

use hal;
use crate::prelude::*;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("bip39", "BIP-39 mnemonics")
		.subcommand(cmd_generate())
		.subcommand(cmd_get_seed())
}

pub fn execute<'a>(args: &clap::ArgMatches<'a>) {
	match args.subcommand() {
		("generate", Some(ref m)) => exec_generate(&m),
		("get-seed", Some(ref m)) => exec_get_seed(&m),
		(_, _) => unreachable!("clap prints help"),
	};
}

fn cmd_generate<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("generate", "generate a new BIP-39 mnemonic")
		.unset_setting(clap::AppSettings::ArgRequiredElseHelp)
		.arg(args::opt_yaml())
		.arg(args::arg("words", "the number of words").long("words").short("w").default_value("24"))
		.arg(args::arg("entropy", "hex-encoded entropy data").long("entropy"))
		.arg(args::opt("stdin", "read entropy from stdin"))
}

fn exec_generate<'a>(args: &clap::ArgMatches<'a>) {
	let network = args.network();

	let word_count = args.value_of("words").unwrap_or("24").parse::<usize>()
		.need("invalid number of words");
	if word_count < 12 || word_count % 6 != 0 || word_count > 24 {
		exit!("invalid word count: {}", word_count);
	}
	let nb_entropy_bytes = (word_count / 3) * 4;

	let mut entropy;
	match (args.is_present("entropy"), args.is_present("stdin")) {
		(true, true) => exit!("can't provide --entropy and --stdin"),
		(true, false) => {
			let entropy_hex = args.value_of("entropy").unwrap();
			if entropy_hex.len() != nb_entropy_bytes * 2 {
				exit!(
					"invalid entropy length for {} word mnemonic, need {} bytes",
					word_count, nb_entropy_bytes
				);
			}
			entropy = hex::decode(&entropy_hex).need("invalid entropy hex");
		}
		(false, true) => {
			let mut hasher = sha256::Hash::engine();
			let stdin = io::stdin();
			let read = io::copy(&mut stdin.lock(), &mut hasher).need("error reading stdin");
			if read < nb_entropy_bytes as u64 {
				warn!("Low entropy provided! Do not use this mnemonic in production!");
			}
			entropy = sha256::Hash::from_engine(hasher)[0..nb_entropy_bytes].to_vec();
		}
		(false, false) => {
			entropy = vec![0; nb_entropy_bytes];
			rand::thread_rng().fill_bytes(&mut entropy);
		}
	}

	assert!(entropy.len() == nb_entropy_bytes);
	let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy).unwrap();
	args.print_output(&hal::GetInfo::get_info(&mnemonic, network))
}

fn cmd_get_seed<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand(
		"get-seed",
		"get the seed value and BIP-32 master key for a given BIP-39 mnemonic",
	)
	.arg(args::arg("mnemonic", "the mnemonic phrase").required(true))
	.arg(args::arg("passphrase", "the BIP-39 passphrase").long("passphrase"))
	.arg(args::opt_yaml())
}

fn exec_get_seed<'a>(args: &clap::ArgMatches<'a>) {
	let network = args.network();

	let mnemonic = args.value_of("mnemonic").need("no mnemonic provided");
	let mnemonic = Mnemonic::parse(mnemonic)
		.need("invalid mnemonic phrase");

	let info = ::hal::bip39::MnemonicInfo::from_mnemonic_with_passphrase(
		&mnemonic,
		args.value_of("passphrase").unwrap_or(""),
		network,
	);
	args.print_output(&info)
}
