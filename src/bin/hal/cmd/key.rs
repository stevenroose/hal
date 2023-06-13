use std::io::Write;
use std::process;
use std::str::FromStr;

use bitcoin::secp256k1;
use bitcoin::hashes::hex::FromHex;
use bitcoin::{PrivateKey, PublicKey};
use clap;
use rand;

use hal::{self, GetInfo};

use crate::prelude::*;


pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("key", "work with private and public keys")
		.subcommand(cmd_generate())
		.subcommand(cmd_derive())
		.subcommand(cmd_inspect())
		.subcommand(cmd_sign())
		.subcommand(cmd_verify())
		.subcommand(cmd_negate_pubkey())
		.subcommand(cmd_pubkey_tweak_add())
		.subcommand(cmd_pubkey_combine())
}

pub fn execute<'a>(args: &clap::ArgMatches<'a>) {
	match args.subcommand() {
		("generate", Some(ref m)) => exec_generate(&m),
		("derive", Some(ref m)) => exec_derive(&m),
		("inspect", Some(ref m)) => exec_inspect(&m),
		("sign", Some(ref m)) => exec_sign(&m),
		("verify", Some(ref m)) => exec_verify(&m),
		("negate-pubkey", Some(ref m)) => exec_negate_pubkey(&m),
		("pubkey-tweak-add", Some(ref m)) => exec_pubkey_tweak_add(&m),
		("pubkey-combine", Some(ref m)) => exec_pubkey_combine(&m),
		(_, _) => unreachable!("clap prints help"),
	};
}

fn cmd_generate<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("generate", "generate a new ECDSA keypair")
		.unset_setting(clap::AppSettings::ArgRequiredElseHelp)
		.args(&args::opts_networks())
		.args(&[args::opt_yaml()])
}

fn exec_generate<'a>(args: &clap::ArgMatches<'a>) {
	let network = args.network();

	let entropy: [u8; 32] = rand::random();
	let secret_key = secp256k1::SecretKey::from_slice(&entropy[..]).unwrap();
	let privkey = bitcoin::PrivateKey {
		compressed: true,
		network: network,
		inner: secret_key,
	};

	let info = privkey.get_info(network);
	args.print_output(&info)
}

fn cmd_derive<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("derive", "generate a public key from a private key")
		.args(&args::opts_networks())
		.args(&[args::opt_yaml(), args::arg("privkey", "the secret key").required(true)])
}

fn exec_derive<'a>(args: &clap::ArgMatches<'a>) {
	let network = args.network();

	let privkey = {
		let s = args.value_of("privkey").expect("no private key provided");
		bitcoin::PrivateKey::from_str(&s).unwrap_or_else(|_| {
			bitcoin::PrivateKey {
				compressed: true,
				network: network,
				inner: secp256k1::SecretKey::from_str(&s)
					.expect("invalid private key provided"),
			}
		})
	};

	let info = privkey.get_info(network);
	args.print_output(&info)
}

fn cmd_inspect<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("inspect", "inspect private keys")
		.args(&[args::opt_yaml(), args::arg("key", "the key").required(true)])
}

fn exec_inspect<'a>(args: &clap::ArgMatches<'a>) {
	let raw = args.value_of("key").expect("no key provided");

	let info = if let Ok(privkey) = PrivateKey::from_str(&raw) {
		privkey.get_info(privkey.network)
	} else if let Ok(sk) = secp256k1::SecretKey::from_str(&raw) {
		sk.get_info(args.network())
	} else {
		exit!("invalid WIF/hex private key: {}", raw);
	};

	args.print_output(&info)
}

fn cmd_sign<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand(
		"sign",
		"sign messages\n\nNOTE!! For SHA-256-d hashes, the --reverse \
		flag must be used because Bitcoin Core reverses the hex order for those!",
	)
	.args(&[
		args::opt_yaml(),
		args::opt("reverse", "reverse the message"),
		args::arg("privkey", "the private key in hex or WIF").required(true),
		args::arg("message", "the message to be signed in hex (must be 32 bytes)").required(true),
	])
}

fn exec_sign<'a>(args: &clap::ArgMatches<'a>) {
	let network = args.network();

	let msg_hex = args.value_of("message").expect("no message given");
	let mut msg_bytes = hex::decode(&msg_hex).expect("invalid hex message");
	if args.is_present("reverse") {
		msg_bytes.reverse();
	}
	let msg = secp256k1::Message::from_slice(&msg_bytes[..]).expect("invalid message to be signed");

	let privkey = {
		let s = args.value_of("privkey").expect("no private key provided");
		bitcoin::PrivateKey::from_str(&s).unwrap_or_else(|_| {
			bitcoin::PrivateKey {
				compressed: true,
				network: network,
				inner: secp256k1::SecretKey::from_str(&s).expect("invalid private key provided"),
			}
		})
	};

	let signature = SECP.sign_ecdsa(&msg, &privkey.inner);
	args.print_output(&signature.get_info(network))
}

fn cmd_verify<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand(
		"verify",
		"verify ecdsa signatures\n\nNOTE!! For SHA-256-d hashes, the --reverse \
		flag must be used because Bitcoin Core reverses the hex order for those!",
	)
	.args(&[
		args::opt_yaml(),
		args::opt("reverse", "reverse the message"),
		args::opt("no-try-reverse", "don't try to verify for reversed message"),
		args::arg("message", "the message to be signed in hex (must be 32 bytes)").required(true),
		args::arg("pubkey", "the public key in hex").required(true),
		args::arg("signature", "the ecdsa signature in hex").required(true),
	])
}

fn exec_verify<'a>(args: &clap::ArgMatches<'a>) {
	let msg_hex = args.value_of("message").expect("no message given");
	let mut msg_bytes = hex::decode(&msg_hex).expect("invalid hex message");
	if args.is_present("reverse") {
		msg_bytes.reverse();
	}
	let msg = secp256k1::Message::from_slice(&msg_bytes[..]).expect("invalid message to be signed");
	let pubkey_hex = args.value_of("pubkey").expect("no public key provided");
	let pubkey = pubkey_hex.parse::<PublicKey>().expect("invalid public key");
	let sig = {
		let hex = args.value_of("signature").expect("no signature provided");
		let bytes = hex::decode(&hex).expect("invalid signature: not hex");
		if bytes.len() == 64 {
			secp256k1::ecdsa::Signature::from_compact(&bytes).expect("invalid signature")
		} else {
			secp256k1::ecdsa::Signature::from_der(&bytes).expect("invalid DER signature")
		}
	};

	let valid = SECP.verify_ecdsa(&msg, &sig, &pubkey.inner).is_ok();

	// Perhaps the user should have passed --reverse.
	if !valid && !args.is_present("no-try-reverse") {
		msg_bytes.reverse();
		let msg = secp256k1::Message::from_slice(&msg_bytes[..])
			.expect("invalid message to be signed");
		if SECP.verify_ecdsa(&msg, &sig, &pubkey.inner).is_ok() {
			eprintln!("Signature is valid for the reverse message.");
			if args.is_present("reverse") {
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

fn cmd_negate_pubkey<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("negate-pubkey", "negate the public key")
		.args(&[args::opt_yaml(), args::arg("pubkey", "the public key").required(true)])
}

fn exec_negate_pubkey<'a>(args: &clap::ArgMatches<'a>) {
	let s = args.value_of("pubkey").expect("no public key provided");
	let key = PublicKey::from_str(&s).expect("invalid public key");

	let negated = key.inner.negate(&SECP);

	write!(::std::io::stdout(), "{}", negated).expect("failed to write stdout");
}

fn cmd_pubkey_tweak_add<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("pubkey-tweak-add", "add a scalar (private key) to a point (public key)").args(
		&[
			args::opt_yaml(),
			args::arg("point", "the public key in hex").required(true),
			args::arg("scalar", "the private key in hex").required(true),
		],
	)
}

fn exec_pubkey_tweak_add<'a>(args: &clap::ArgMatches<'a>) {
	let point = {
		let hex = args.value_of("point").expect("no point provided");
		hex.parse::<PublicKey>().expect("invalid point")
	};

	let scalar = {
		let hex = args.value_of("scalar").expect("no scalar given");
		let bytes = <[u8; 32]>::from_hex(hex).expect("invalid scalar hex");
		secp256k1::Scalar::from_be_bytes(bytes).expect("invalid scalar")
	};

	match point.inner.add_exp_tweak(&SECP, &scalar.into()) {
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
		args::opt_yaml(),
		args::arg("pubkey1", "the first public key in hex").required(true),
		args::arg("pubkey2", "the second public key in hex").required(true),
	])
}

fn exec_pubkey_combine<'a>(args: &clap::ArgMatches<'a>) {
	let pk1 = {
		let hex = args.value_of("pubkey1").expect("no first public key provided");
		hex.parse::<PublicKey>().expect("invalid first public key")
	};

	let pk2 = {
		let hex = args.value_of("pubkey2").expect("no second public key provided");
		hex.parse::<PublicKey>().expect("invalid second public key")
	};

	match pk1.inner.combine(&pk2.inner) {
		Ok(sum) => {
			eprintln!("{}", sum.to_string());
		}
		Err(err) => {
			eprintln!("error: {}", err);
			process::exit(1);
		}
	}
}
