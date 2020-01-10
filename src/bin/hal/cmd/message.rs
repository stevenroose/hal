use bitcoin::secp256k1;
use bitcoin::{PrivateKey, PublicKey};
use clap;

use cmd;
use hal::message::SignedMessageInfo;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("message", "Bitcoin Signed Messages")
		.subcommand(cmd_sign())
		.subcommand(cmd_verify())
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	match matches.subcommand() {
		("sign", Some(ref m)) => exec_sign(&m),
		("verify", Some(ref m)) => exec_verify(&m),
		(_, _) => unreachable!("clap prints help"),
	};
}

fn cmd_sign<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("sign", "create a new Bitcoin Signed Message").args(&[
		cmd::opt_yaml(),
		cmd::arg("key", "the private key to sign with in WIF format").required(true),
		cmd::arg("message", "the message to sign (without prefix)").required(true),
	])
}

fn exec_sign<'a>(matches: &clap::ArgMatches<'a>) {
	let wif = matches.value_of("key").expect("no key provided");
	let privkey: PrivateKey = wif.parse().expect("invalid WIF format");

	let msg = matches.value_of("message").expect("no message provided");
	let hash = bitcoin::util::misc::signed_msg_hash(&msg);

	let secp = secp256k1::Secp256k1::new();
	let signature = secp.sign(&secp256k1::Message::from_slice(&hash).unwrap(), &privkey.key);

	let info = SignedMessageInfo {
		message: msg.to_owned(),
		public_key: privkey.public_key(&secp),
		signature_der_hex: signature.serialize_der()[..].into(),
		signature_der_base64: base64::encode(&signature.serialize_der()[..]),
		signature_compact_hex: signature.serialize_compact()[..].into(),
		signature_compact_base64: base64::encode(&signature.serialize_compact()[..]),
	};

	cmd::print_output(matches, &info)
}

fn cmd_verify<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("verify", "verify Bitcoin Signed Messages").args(&[
		cmd::arg("pubkey", "the public key in hex").required(true),
		cmd::arg("signature", "the signature in hex").required(true),
		cmd::arg("message", "the message that was signed (without prefix)").required(true),
	])
}

fn exec_verify<'a>(matches: &clap::ArgMatches<'a>) {
	let pubkey_hex = matches.value_of("pubkey").expect("no public key provided");
	let pubkey: PublicKey = pubkey_hex.parse().expect("invalid public key");

	let sig = matches.value_of("signature").expect("no signature provided");
	let sig_bytes = match (hex::decode(&sig), base64::decode(&sig)) {
		(Ok(b), Err(_)) => b,
		(Err(_), Ok(b)) => b,
		(Ok(b), Ok(_)) => {
			debug!("Signature is both valid hex and base64, assuming it's hex.");
			b
		}
		(Err(e1), Err(e2)) => panic!("Invalid signature: \"{}\"; \"{}\"", e1, e2),
	};
	let signature = if sig_bytes.len() == 64 {
		secp256k1::Signature::from_compact(&sig_bytes).expect("invalid compact signature")
	} else {
		secp256k1::Signature::from_der(&sig_bytes).expect("invalid DER signature")
	};

	let msg = matches.value_of("message").expect("no message given");
	let hash = bitcoin::util::misc::signed_msg_hash(&msg);

	let secp = secp256k1::Secp256k1::verification_only();
	secp.verify(&secp256k1::Message::from_slice(&hash).unwrap(), &signature, &pubkey.key)
		.expect("invalid signature")
}
