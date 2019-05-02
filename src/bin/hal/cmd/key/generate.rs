use bitcoin::Address;
use clap;
use rand;
use secp256k1;

use cmd;
use hal;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("generate", "generate a new ECDSA keypair")
		.unset_setting(clap::AppSettings::ArgRequiredElseHelp)
		.args(&cmd::opts_networks())
		.args(&[cmd::opt_yaml()])
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	let network = cmd::network(matches);

	let secp = secp256k1::Secp256k1::new();
	let secret_key = secp256k1::SecretKey::new(&mut rand::thread_rng());

	let privkey = bitcoin::PrivateKey {
		compressed: true,
		network: network,
		key: secret_key,
	};
	let pubkey = privkey.public_key(&secp);

	let info = hal::key::GeneratedKeyPair {
		raw_private_key: (&secret_key[..]).into(),
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
