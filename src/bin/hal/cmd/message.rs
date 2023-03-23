use std::str::FromStr;

use bitcoin::secp256k1;
use bitcoin::{Address, AddressType, PrivateKey, PublicKey};
use clap;

use crate::{cmd, util};

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("message", "Bitcoin Signed Messages")
		.subcommand(cmd_hash())
		.subcommand(cmd_sign())
		.subcommand(cmd_verify())
		.subcommand(cmd_recover())
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	match matches.subcommand() {
		("hash", Some(ref m)) => exec_hash(&m),
		("sign", Some(ref m)) => exec_sign(&m),
		("verify", Some(ref m)) => exec_verify(&m),
		("recover", Some(ref m)) => exec_recover(&m),
		(_, _) => unreachable!("clap prints help"),
	};
}

fn cmd_hash<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("hash", "calculate Bitcoin Signed Message hash").args(&[
		cmd::opt_yaml(),
		cmd::arg("message", "the message to sign (without prefix)").required(true),
	])
}

fn exec_hash<'a>(matches: &clap::ArgMatches<'a>) {
	use bitcoin::hashes::Hash;
	let msg = matches.value_of("message").expect("no message provided");
	let res = hal::message::MessageHash {
		sha256: bitcoin::hashes::sha256::Hash::hash(msg.as_bytes()),
		sha256d: bitcoin::hashes::sha256d::Hash::hash(msg.as_bytes()),
		sign_hash: bitcoin::util::misc::signed_msg_hash(&msg),
	};

	cmd::print_output(matches, &res)
}

fn cmd_sign<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("sign", "create a new Bitcoin Signed Message").args(&[
		cmd::arg("key", "the private key to sign with in WIF format").required(true),
		cmd::arg("message", "the message to sign (without prefix)").required(false),
	])
}

fn exec_sign<'a>(matches: &clap::ArgMatches<'a>) {
	let wif = matches.value_of("key").expect("no key provided");
	let privkey: PrivateKey = wif.parse().expect("invalid WIF format");

	let msg = util::arg_or_stdin(matches, "message");
	let hash = bitcoin::util::misc::signed_msg_hash(&msg);

	let secp = secp256k1::Secp256k1::new();
	let signature =
		secp.sign_ecdsa_recoverable(&secp256k1::Message::from_slice(&hash).unwrap(), &privkey.inner);

	let (recid, raw) = signature.serialize_compact();
	let mut serialized = [0u8; 65];
	serialized[0] = 27;
	serialized[0] += recid.to_i32() as u8;
	if privkey.compressed {
		serialized[0] += 4;
	}
	serialized[1..].copy_from_slice(&raw[..]);

	print!("{}", base64::encode(&serialized[..]));
}

fn cmd_verify<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("verify", "recover the pubkey and address of a Bitcoin Signed Messages")
		.args(&cmd::opts_networks())
		.args(&[
			cmd::arg("signer", "the signer's public key or address").required(true),
			cmd::arg("signature", "the signature in hex").required(true),
			cmd::arg("message", "the message that was signed (without prefix)").required(false),
		])
}

fn exec_verify<'a>(matches: &clap::ArgMatches<'a>) {
	let signer = matches.value_of("signer").expect("no signer provided");
	let signer_addr_res = Address::from_str(&signer);
	let signer_pubk_res = PublicKey::from_str(&signer);
	if signer_addr_res.is_err() && signer_pubk_res.is_err() {
		if let Err(e) = signer_addr_res {
			error!("Error parsing signer as address: {}", e);
		}
		if let Err(e) = signer_pubk_res {
			error!("Error parsing signer as public key: {}", e);
		}
		panic!("Failed to parse signer.");
	}
	if signer_addr_res.is_ok() && signer_pubk_res.is_ok() {
		debug!("Rare/impossible case that signer can both be parsed as pubkey and address.");
	}

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

	if sig_bytes.len() != 65 {
		panic!("Invalid signature: length is {} instead of 65 bytes", sig_bytes.len());
	}
	let recid = secp256k1::ecdsa::RecoveryId::from_i32(((sig_bytes[0] - 27) & 0x03) as i32)
		.expect("invalid recoverable signature (invalid recid)");
	let compressed = ((sig_bytes[0] - 27) & 0x04) != 0;
	let signature = secp256k1::ecdsa::RecoverableSignature::from_compact(&sig_bytes[1..], recid)
		.expect("invalid recoverable signature");

	let msg = util::arg_or_stdin(matches, "message");
	let hash = bitcoin::util::misc::signed_msg_hash(&msg);

	let secp = secp256k1::Secp256k1::verification_only();
	let pubkey = PublicKey {
		inner: secp
			.recover_ecdsa(&secp256k1::Message::from_slice(&hash).unwrap(), &signature)
			.expect("invalid signature"),
		compressed: compressed,
	};

	let network = cmd::network(matches);
	if let Ok(pk) = signer_pubk_res {
		if pubkey != pk {
			panic!("Signed for pubkey {}, expected {}", pubkey, pk);
		}
	} else if let Ok(expected) = signer_addr_res {
		let addr = match expected.address_type() {
			None => panic!("Unknown address type provided"),
			Some(AddressType::P2pkh) => Address::p2pkh(&pubkey, network),
			Some(AddressType::P2wpkh) => {
				Address::p2wpkh(&pubkey, network).expect("Uncompressed key in Segwit")
			}
			Some(AddressType::P2sh) => {
				Address::p2shwpkh(&pubkey, network).expect("Uncompressed key in Segwit")
			}
			Some(tp) => panic!("Address of type {} can't sign messages.", tp),
		};
		// We need to use to_string because regtest and testnet addresses are the same.
		if addr.to_string() != expected.to_string() {
			panic!(
				"Signed for address {:?}, expected {:?} ({})",
				addr,
				expected,
				expected.address_type().map(|t| t.to_string()).unwrap_or("unknown type".into()),
			);
		}
	} else {
		unreachable!();
	}
	eprintln!("Signature is valid.");
}

fn cmd_recover<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("recover", "recover the pubkey and address of a Bitcoin Signed Messages")
		.args(&cmd::opts_networks())
		.args(&[
			cmd::arg("signature", "the signature in hex").required(true),
			cmd::arg("message", "the message that was signed (without prefix)").required(true),
		])
}

fn exec_recover<'a>(matches: &clap::ArgMatches<'a>) {
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

	if sig_bytes.len() != 65 {
		panic!("Invalid signature: length is {} instead of 65 bytes", sig_bytes.len());
	}
	let recid = secp256k1::ecdsa::RecoveryId::from_i32((sig_bytes[0] - 27 & 0x03) as i32)
		.expect("invalid recoverable signature (invalid recid)");
	let compressed = sig_bytes[0] & 0x04 != 0x04;
	let signature = secp256k1::ecdsa::RecoverableSignature::from_compact(&sig_bytes[1..], recid)
		.expect("invalid recoverable signature");

	let msg = matches.value_of("message").expect("no message given");
	let hash = bitcoin::util::misc::signed_msg_hash(&msg);

	let secp = secp256k1::Secp256k1::verification_only();
	let pubkey = secp
		.recover_ecdsa(&secp256k1::Message::from_slice(&hash).unwrap(), &signature)
		.expect("invalid signature");

	let bitcoin_key = PublicKey {
		inner: pubkey,
		compressed: compressed,
	};
	let info = hal::GetInfo::get_info(&bitcoin_key, cmd::network(matches));
	cmd::print_output(matches, &info)
}
