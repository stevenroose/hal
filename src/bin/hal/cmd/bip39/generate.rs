use std::io;

use bip39;
use bitcoin::hashes::{sha256, Hash};
use clap;
use hex;
use rand::Rng;

use cmd;
use hal;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("generate", "generate a new BIP-39 mnemonic")
		.unset_setting(clap::AppSettings::ArgRequiredElseHelp)
		.arg(cmd::arg("words", "the number of words").long("words").short("w").default_value("24"))
		.arg(cmd::arg("entropy", "hex-encoded entropy data").long("entropy"))
		.arg(cmd::opt("stdin", "read entropy from stdin"))
		.args(&cmd::opts_networks())
		.args(&[cmd::opt_yaml()])
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	let network = cmd::network(matches);

	let nb_words: usize =
		matches.value_of("words").unwrap_or("24").parse().expect("invalid number of words");
	let mnem_type = bip39::MnemonicType::for_word_count(nb_words).expect("invalid number of words");
	let nb_entropy_bytes = (mnem_type.entropy_bits() / 8) as usize;
	assert!(nb_entropy_bytes <= 32, "{} > 32", nb_entropy_bytes);

	let mut entropy;
	match (matches.is_present("entropy"), matches.is_present("stdin")) {
		(true, true) => panic!("can't provide --entropy and --stdin"),
		(true, false) => {
			let entropy_hex = matches.value_of("entropy").unwrap();
			if entropy_hex.len() != nb_entropy_bytes * 2 {
				panic!(
					"invalid entropy length for {} word mnemonic, need {} bytes",
					nb_words, nb_entropy_bytes
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
	let mnemonic = bip39::Mnemonic::from_entropy(&entropy, bip39::Language::English).unwrap();
	cmd::print_output(matches, &hal::GetInfo::get_info(&mnemonic, network))
}
