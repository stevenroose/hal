use std::process;
use std::str::FromStr;

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
		.subcommand(cmd_sign())
		.subcommand(cmd_verify())
		.subcommand(cmd_pubkey_tweak_add())
		.subcommand(cmd_pubkey_combine())
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	match matches.subcommand() {
		("generate", Some(ref m)) => exec_generate(&m),
		("inspect", Some(ref m)) => exec_inspect(&m),
		("sign", Some(ref m)) => exec_sign(&m),
		("verify", Some(ref m)) => exec_verify(&m),
		("pubkey-tweak-add", Some(ref m)) => exec_pubkey_tweak_add(&m),
		("pubkey-combine", Some(ref m)) => exec_pubkey_combine(&m),
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
		wif_private_key: Some(privkey),
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
	let raw = matches.value_of("key").expect("no key provided");

	let info = if let Ok(privkey) = PrivateKey::from_str(&raw) {
		let network = privkey.network;
		let pubkey = privkey.public_key(&secp256k1::Secp256k1::new());

		hal::key::KeyInfo {
			raw_private_key: (&privkey.key[..]).into(),
			wif_private_key: Some(privkey),
			public_key: pubkey,
			uncompressed_public_key: {
				let mut uncompressed = pubkey.clone();
				uncompressed.compressed = false;
				uncompressed
			},
			addresses: hal::address::Addresses::from_pubkey(&pubkey, network),
		}
	} else if let Ok(sk) = secp256k1::SecretKey::from_str(&raw) {
		let pubkey = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &sk);
		let btc_pubkey = PublicKey {
			compressed: true,
			key: pubkey.clone(),
		};
		let network = cmd::network(matches);
		hal::key::KeyInfo {
			raw_private_key: sk[..].into(),
			wif_private_key: None,
			public_key: btc_pubkey,
			uncompressed_public_key: PublicKey {
				compressed: false,
				key: pubkey,
			},
			addresses: hal::address::Addresses::from_pubkey(&btc_pubkey, network),
		}
	} else {
		panic!("invalid WIF/hex private key: {}", raw);
	};

	cmd::print_output(matches, &info)
}

fn cmd_sign<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand(
		"sign",
		"sign messages\n\nNOTE!! For SHA-256-d hashes, the --reverse \
		flag must be used because Bitcoin Core reverses the hex order for those!",
	)
	.args(&[
		cmd::opt_yaml(),
		cmd::opt("reverse", "reverse the message"),
		cmd::arg("privkey", "the private key in hex or WIF").required(true),
		cmd::arg("message", "the message to be signed in hex (must be 32 bytes)").required(true),
	])
}

fn exec_sign<'a>(matches: &clap::ArgMatches<'a>) {
	let msg_hex = matches.value_of("message").expect("no message given");
	let mut msg_bytes = hex::decode(&msg_hex).expect("invalid hex message");
	if matches.is_present("reverse") {
		msg_bytes.reverse();
	}
	let msg = secp256k1::Message::from_slice(&msg_bytes[..]).expect("invalid message to be signed");
	let privkey = {
		let pk = matches.value_of("privkey").expect("no private key provided");
		if let Ok(sk) = secp256k1::SecretKey::from_str(&pk) {
			sk
		} else {
			bitcoin::PrivateKey::from_wif(&pk).expect("invalid private key provided").key
		}
	};

	let secp = secp256k1::Secp256k1::signing_only();
	let signature = secp.sign(&msg, &privkey);

	let info = hal::key::SignatureInfo {
		der: signature.serialize_der().as_ref().into(),
		compact: signature.serialize_compact().to_vec().into(),
	};
	cmd::print_output(matches, &info)
}

fn cmd_verify<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand(
		"verify",
		"verify signatures\n\nNOTE!! For SHA-256-d hashes, the --reverse \
		flag must be used because Bitcoin Core reverses the hex order for those!",
	)
	.args(&[
		cmd::opt_yaml(),
		cmd::opt("reverse", "reverse the message"),
		cmd::opt("no-try-reverse", "don't try to verify for reversed message"),
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
	let sig = {
		let hex = matches.value_of("signature").expect("no signature provided");
		let bytes = hex::decode(&hex).expect("invalid signature: not hex");
		if bytes.len() == 64 {
			secp256k1::Signature::from_compact(&bytes).expect("invalid signature")
		} else {
			secp256k1::Signature::from_der(&bytes).expect("invalid DER signature")
		}
	};

	let secp = secp256k1::Secp256k1::verification_only();
	let valid = secp.verify(&msg, &sig, &pubkey.key).is_ok();

	// Perhaps the user should have passed --reverse.
	if !valid && !matches.is_present("no-try-reverse") {
		msg_bytes.reverse();
		let msg =
			secp256k1::Message::from_slice(&msg_bytes[..]).expect("invalid message to be signed");
		if secp.verify(&msg, &sig, &pubkey.key).is_ok() {
			eprintln!("Signature is valid for the reverse message.");
			if matches.is_present("reverse") {
				eprintln!("Try dropping the --reverse");
			} else {
				eprintln!("If the message is a Bitcoin SHA256 hash, try --reverse");
			}
		}
	}

	if valid {
		eprintln!("Signature is valid.");
	} else {
		eprintln!("Signature is invalid!");
		process::exit(1);
	}
}

fn cmd_pubkey_tweak_add<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("pubkey-tweak-add", "add a scalar (private key) to a point (public key)").args(
		&[
			cmd::opt_yaml(),
			cmd::arg("point", "the public key in hex").required(true),
			cmd::arg("scalar", "the private key in hex").required(true),
		],
	)
}

fn exec_pubkey_tweak_add<'a>(matches: &clap::ArgMatches<'a>) {
	let point_hex = matches.value_of("point").expect("no point provided");
	let mut point: PublicKey = point_hex.parse().expect("invalid point");

	let scalar_hex = matches.value_of("scalar").expect("no scalar given");
	let scalar_bytes = hex::decode(&scalar_hex).expect("invalid hex scalar");

	let secp = secp256k1::Secp256k1::verification_only();
	match point.key.add_exp_assign(&secp, &scalar_bytes) {
		Ok(..) => {
			eprintln!("{}", point.to_string());
		}
		Err(err) => {
			eprintln!("error: {}", err);
			process::exit(1);
		}
	}
}

fn cmd_pubkey_combine<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("pubkey-combine", "add a point (public key) to another").args(&[
		cmd::opt_yaml(),
		cmd::arg("pubkey1", "the first public key in hex").required(true),
		cmd::arg("pubkey2", "the second public key in hex").required(true),
	])
}

fn exec_pubkey_combine<'a>(matches: &clap::ArgMatches<'a>) {
	let pubkey1_hex = matches.value_of("pubkey1").expect("no first public key provided");
	let pubkey1: PublicKey = pubkey1_hex.parse().expect("invalid first public key");

	let pubkey2_hex = matches.value_of("pubkey2").expect("no second public key provided");
	let pubkey2: PublicKey = pubkey2_hex.parse().expect("invalid second public key");

	match pubkey1.key.combine(&pubkey2.key) {
		Ok(sum) => {
			eprintln!("{}", sum.to_string());
		}
		Err(err) => {
			eprintln!("error: {}", err);
			process::exit(1);
		}
	}
}
