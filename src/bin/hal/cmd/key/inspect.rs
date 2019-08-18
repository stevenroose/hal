use bitcoin::{Address, PrivateKey};
use clap;

use cmd;
use hal;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("inspect", "inspect private keys")
		.args(&[cmd::opt_yaml(), cmd::arg("key", "the key").required(true)])
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	let wif = matches.value_of("key").expect("no key provided");
	let privkey: PrivateKey = wif.parse().expect("invalid WIF format");

	let network = privkey.network;
	let pubkey = privkey.public_key(&secp256k1::Secp256k1::new());

	let info = hal::key::KeyInfo {
		raw_private_key: (&privkey.key[..]).into(),
		wif_private_key: privkey,
		public_key: pubkey,
		compressed_public_key: pubkey,
		uncompressed_public_key: {
			let mut uncompressed = pubkey.clone();
			uncompressed.compressed = false;
			uncompressed
		},
		addresses: hal::address::CreatedAddresses {
			p2pkh: Some(Address::p2pkh(&pubkey, network).to_string()),
			p2wpkh: Some(Address::p2wpkh(&pubkey, network).to_string()),
			p2shwpkh: Some(Address::p2shwpkh(&pubkey, network).to_string()),
			..Default::default()
		},
	};

	cmd::print_output(matches, &info)
}
