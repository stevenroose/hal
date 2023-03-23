use std::io;

use bip39::{Language, Mnemonic};
use bitcoin::hashes::{sha256, Hash};
use clap;
use hex;
use rand::Rng;

use hal;
use crate::cmd;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("bip39", "BIP-39 mnemonics")
		.subcommand(cmd_generate())
		.subcommand(cmd_get_seed())
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	match matches.subcommand() {
		("generate", Some(ref m)) => exec_generate(&m),
		("get-seed", Some(ref m)) => exec_get_seed(&m),
		(_, _) => unreachable!("clap prints help"),
	};
}

fn cmd_generate<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("generate", "generate a new BIP-39 mnemonic")
		.unset_setting(clap::AppSettings::ArgRequiredElseHelp)
		.arg(cmd::arg("words", "the number of words").long("words").short("w").default_value("24"))
		.arg(cmd::arg("entropy", "hex-encoded entropy data").long("entropy"))
		.arg(cmd::opt("stdin", "read entropy from stdin"))
		.args(&cmd::opts_networks())
		.args(&[cmd::opt_yaml()])
}

fn exec_generate<'a>(matches: &clap::ArgMatches<'a>) {
	let network = cmd::network(matches);

	let word_count = matches.value_of("words").unwrap_or("24").parse::<usize>()
		.expect("invalid number of words");
	if word_count < 12 || word_count % 6 != 0 || word_count > 24 {
		panic!("invalid word count: {}", word_count);
	}
	let nb_entropy_bytes = (word_count / 3) * 4;

	let mut entropy;
	match (matches.is_present("entropy"), matches.is_present("stdin")) {
		(true, true) => panic!("can't provide --entropy and --stdin"),
		(true, false) => {
			let entropy_hex = matches.value_of("entropy").unwrap();
			if entropy_hex.len() != nb_entropy_bytes * 2 {
				panic!(
					"invalid entropy length for {} word mnemonic, need {} bytes",
					word_count, nb_entropy_bytes
				);
			}
			entropy = hex::decode(&entropy_hex).expect("invalid entropy hex");
		}
		(false, true) => {
			let mut hasher = sha256::Hash::engine();
			let stdin = io::stdin();
			let read = io::copy(&mut stdin.lock(), &mut hasher).expect("error reading stdin");
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
	cmd::print_output(matches, &hal::GetInfo::get_info(&mnemonic, network))
}

fn cmd_get_seed<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand(
		"get-seed",
		"get the seed value and BIP-32 master key for a given BIP-39 mnemonic",
	)
	.args(&[
		cmd::arg("mnemonic", "the mnemonic phrase").required(true),
		cmd::arg("passphrase", "the BIP-39 passphrase").long("passphrase"),
		cmd::opt_yaml(),
	])
	.args(&cmd::opts_networks())
}

fn exec_get_seed<'a>(matches: &clap::ArgMatches<'a>) {
	let network = cmd::network(matches);

	let mnemonic = matches.value_of("mnemonic").expect("no mnemonic provided");
	let mnemonic = Mnemonic::parse(mnemonic)
		.expect("invalid mnemonic phrase");

	let info = ::hal::bip39::MnemonicInfo::from_mnemonic_with_passphrase(
		&mnemonic,
		matches.value_of("passphrase").unwrap_or(""),
		network,
	);
	cmd::print_output(matches, &info)
}
