use std::io;

use bip39::Mnemonic;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::rand::{self, RngCore};
use clap;
use hex;

use hal;
use crate::prelude::*;

/// List of languages we support.
const LANGUAGES: &[&'static str] = &[
	"english",
	"czech",
	"french",
	"italian",
	"japanese",
	"korean",
	"spanish",
	"simplified-chinese",
	"traditional-chinese",
];

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
	lazy_static! {
		static ref LANGUAGE_HELP: String = format!(
			"the language to use for the mnemonic. \
			Supported languages are: {}", LANGUAGES.join(", "),
		);
	}

	cmd::subcommand("generate", "generate a new BIP-39 mnemonic")
		.unset_setting(clap::AppSettings::ArgRequiredElseHelp)
		.arg(args::arg("words", "the number of words")
			.long("words").short("w")
			.default_value("24"))
		.arg(args::arg("language", "the language to use")
			.long("language").short("l")
			.default_value("english")
			.help(&LANGUAGE_HELP))
		.arg(args::arg("entropy", "hex-encoded entropy data").long("entropy"))
		.arg(args::opt("stdin", "read entropy from stdin"))
}

fn exec_generate<'a>(args: &clap::ArgMatches<'a>) {
	let network = args.network();

	let language = {
		let s = args.value_of("language").unwrap_or("en");
		hal::bip39::parse_language(s).need("invalid language string")
	};

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
	let mnemonic = Mnemonic::from_entropy_in(language, &entropy).unwrap();
	args.print_output(&hal::GetInfo::get_info(&mnemonic, network))
}

fn cmd_get_seed<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand(
		"get-seed",
		"get the seed value and BIP-32 master key for a given BIP-39 mnemonic",
	)
	.arg(args::arg("mnemonic", "the mnemonic phrase").required(true))
	.arg(args::arg("passphrase", "the BIP-39 passphrase").long("passphrase"))
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

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_languages() {
		let mut unique = std::collections::HashSet::new();
		for l in LANGUAGES {
			let lang = hal::bip39::parse_language(l).unwrap();
			assert!(unique.insert(lang));
		}
	}
}
