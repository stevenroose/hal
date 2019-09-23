use bip39;
use clap;

use cmd;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("get-seed", "get the seed value and BIP-32 master key for a given BIP-39 mnemonic")
		.args(&[
			cmd::arg("mnemonic", "the mnemonic phrase").required(true),
			cmd::arg("passphrase", "the BIP-39 passphrase").long("passphrase"),
			cmd::opt_yaml(),
		])
		.args(&cmd::opts_networks())
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	let network = cmd::network(matches);

	let phrase = matches.value_of("mnemonic").expect("no mnemonic provided");
	let mnemonic: bip39::Mnemonic = bip39::Mnemonic::from_phrase(phrase, bip39::Language::English)
		.expect("invalid mnemonic phrase");

	let info = ::hal::bip39::MnemonicInfo::from_mnemonic_with_passphrase(
		&mnemonic,
		matches.value_of("passphrase").unwrap_or(""),
		network,
	);
	cmd::print_output(matches, &info)
}
