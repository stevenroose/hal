use bitcoin::{Address, PublicKey};
use clap;

use cmd;
use hal;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("create", "create addresses").args(&cmd::opts_networks()).args(&[
		cmd::opt_yaml(),
		cmd::opt("pubkey", "a public key in hex").takes_value(true).required(false),
		cmd::opt("script", "a script in hex").takes_value(true).required(false),
	])
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	let network = cmd::network(matches);

	let created = if let Some(pubkey_hex) = matches.value_of("pubkey") {
		let pubkey: PublicKey = pubkey_hex.parse().expect("invalid pubkey");
		hal::address::CreatedAddresses {
			p2pkh: Some(Address::p2pkh(&pubkey, network).to_string()),
			p2wpkh: Some(Address::p2wpkh(&pubkey, network).to_string()),
			p2shwpkh: Some(Address::p2shwpkh(&pubkey, network).to_string()),
			..Default::default()
		}
	} else if let Some(script_hex) = matches.value_of("script") {
		let script_bytes = hex::decode(script_hex).expect("invalid script hex");
		let script = script_bytes.into();

		hal::address::CreatedAddresses {
			p2sh: Some(Address::p2sh(&script, network).to_string()),
			p2wsh: Some(Address::p2wsh(&script, network).to_string()),
			p2shwsh: Some(Address::p2shwsh(&script, network).to_string()),
			..Default::default()
		}
	} else {
		panic!("Can't create addresses without a pubkey");
	};

	cmd::print_output(matches, &created)
}
