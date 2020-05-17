use bitcoin::secp256k1;
use bitcoin::{PrivateKey, PublicKey};
use clap;
use rand;

use cmd;
use hal;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("key", "work with private and public keys")
		.subcommand(cmd_generate())
		.subcommand(cmd_inspect())
		.subcommand(cmd_verify())
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	match matches.subcommand() {
		("generate", Some(ref m)) => exec_generate(&m),
		("inspect", Some(ref m)) => exec_inspect(&m),
		("verify", Some(ref m)) => exec_verify(&m),
		(_, _) => unreachable!("clap prints help"),
	};
}

fn cmd_generate<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("generate", "generate a new ECDSA keypair")
		.unset_setting(clap::AppSettings::ArgRequiredElseHelp)
		.args(&cmd::opts_networks())
		.args(&[cmd::opt_yaml()])
}

fn exec_generate<'a>(matches: &clap::ArgMatches<'a>) {
	let network = cmd::network(matches);

	let secp = secp256k1::Secp256k1::signing_only();
	let entropy: [u8; 32] = rand::random();
	let secret_key = secp256k1::SecretKey::from_slice(&entropy[..]).unwrap();

	let privkey = bitcoin::PrivateKey {
		compressed: true,
		network: network,
		key: secret_key,
	};
	let pubkey = privkey.public_key(&secp);

	let info = hal::key::KeyInfo {
		raw_private_key: (&secret_key[..]).into(),
		wif_private_key: privkey,
		public_key: pubkey,
		uncompressed_public_key: {
			let mut uncompressed = pubkey.clone();
			uncompressed.compressed = false;
			uncompressed
		},
		addresses: hal::address::Addresses::from_pubkey(&pubkey, network),
	};

	cmd::print_output(matches, &info)
}

fn cmd_inspect<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("inspect", "inspect private keys")
		.args(&[cmd::opt_yaml(), cmd::arg("key", "the key").required(true)])
}

fn exec_inspect<'a>(matches: &clap::ArgMatches<'a>) {
	let wif = matches.value_of("key").expect("no key provided");
	let privkey: PrivateKey = wif.parse().expect("invalid WIF format");

	let network = privkey.network;
	let pubkey = privkey.public_key(&secp256k1::Secp256k1::new());

	let info = hal::key::KeyInfo {
		raw_private_key: (&privkey.key[..]).into(),
		wif_private_key: privkey,
		public_key: pubkey,
		uncompressed_public_key: {
			let mut uncompressed = pubkey.clone();
			uncompressed.compressed = false;
			uncompressed
		},
		addresses: hal::address::Addresses::from_pubkey(&pubkey, network),
	};

	cmd::print_output(matches, &info)
}

fn cmd_verify<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("verify", "verify signatures\n\nNOTE!! For SHA-256-d hashes, the --reverse \
		flag must be used because Bitcoin Core reverses the hex order for those!").args(&[
		cmd::opt_yaml(),
		cmd::opt("reverse", "reverse the message"),
		cmd::arg("message", "the message to be signed in hex (must be 32 bytes)").required(true),
		cmd::arg("pubkey", "the public key in hex").required(true),
		cmd::arg("signature", "the signature in hex").required(true),
	])
}

fn exec_verify<'a>(matches: &clap::ArgMatches<'a>) {
	let msg_hex = matches.value_of("message").expect("no message given");
	let mut msg_bytes = hex::decode(&msg_hex).expect("invalid hex message");
	if matches.is_present("reverse") {
		msg_bytes.reverse();
	}
	let msg = secp256k1::Message::from_slice(&msg_bytes[..]).expect("invalid message to be signed");
	let pubkey_hex = matches.value_of("pubkey").expect("no public key provided");
	let pubkey: PublicKey = pubkey_hex.parse().expect("invalid public key");
	let sig_hex = matches.value_of("signature").expect("no signature provided");
	let sig: secp256k1::Signature = sig_hex.parse().expect("invalid signature");

	let secp = secp256k1::Secp256k1::verification_only();
	secp.verify(&msg, &sig, &pubkey.key).expect("invalid signature");
	eprintln!("Signature is valid.");
}
