use std::io::Write;
use std::process;

use bitcoin::secp256k1;
use bitcoin::hashes::hex::FromHex;
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
		.arg(args::opt_yaml())
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
		.arg(args::opt_yaml())
		.arg(args::arg("privkey", "the secret key").required(true))
}

fn exec_derive<'a>(args: &clap::ArgMatches<'a>) {
	let network = args.network();
	let privkey = args.need_privkey("privkey");
	let info = privkey.get_info(network);
	args.print_output(&info)
}

fn cmd_inspect<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("inspect", "inspect private keys")
		.args(&[args::opt_yaml(), args::arg("key", "the key").required(true)])
}

fn exec_inspect<'a>(args: &clap::ArgMatches<'a>) {
	let key = args.need_privkey("key");
	let info = key.get_info(args.network());
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

	let msg_hex = args.value_of("message").need("no message given");
	let mut msg_bytes = hex::decode(&msg_hex).need("invalid hex message");
	if args.is_present("reverse") {
		msg_bytes.reverse();
	}
	let msg = secp256k1::Message::from_slice(&msg_bytes[..]).need("invalid message to be signed");
	let privkey = args.need_privkey("privkey");
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
	let msg_hex = args.value_of("message").need("no message given");
	let mut msg_bytes = hex::decode(&msg_hex).need("invalid hex message");
	if args.is_present("reverse") {
		msg_bytes.reverse();
	}
	let msg = secp256k1::Message::from_slice(&msg_bytes[..]).need("invalid message to be signed");
	let pubkey = args.need_pubkey("pubkey");
	let sig = {
		let hex = args.value_of("signature").need("no signature provided");
		let bytes = hex::decode(&hex).need("invalid signature: not hex");
		if bytes.len() == 64 {
			secp256k1::ecdsa::Signature::from_compact(&bytes).need("invalid signature")
		} else {
			secp256k1::ecdsa::Signature::from_der(&bytes).need("invalid DER signature")
		}
	};

	let valid = SECP.verify_ecdsa(&msg, &sig, &pubkey.inner).is_ok();

	// Perhaps the user should have passed --reverse.
	if !valid && !args.is_present("no-try-reverse") {
		msg_bytes.reverse();
		let msg = secp256k1::Message::from_slice(&msg_bytes[..])
			.need("invalid message to be signed");
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
	let key = args.need_pubkey("pubkey");
	let negated = key.inner.negate(&SECP);
	write!(::std::io::stdout(), "{}", negated).need("failed to write stdout");
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
	let point = args.need_pubkey("point");

	let scalar = {
		let hex = args.value_of("scalar").need("no scalar given");
		let bytes = <[u8; 32]>::from_hex(hex).need("invalid scalar hex");
		secp256k1::Scalar::from_be_bytes(bytes).need("invalid scalar")
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
	let pk1 = args.need_pubkey("pubkey1");
	let pk2 = args.need_pubkey("pubkey2");

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
