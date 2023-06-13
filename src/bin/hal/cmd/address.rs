
use std::str::FromStr;

use bitcoin::hashes::Hash;
use bitcoin::hashes::hex::FromHex;
use bitcoin::{Address, PublicKey, WPubkeyHash, WScriptHash};
use clap;

use hal;

use crate::{SECP, cmd, util};

lazy_static! {
	/// The H point as used in BIP-341 which is constructed by taking the hash
	/// of the standard uncompressed encoding of the secp256k1 base point G as
	/// X coordinate.
	///
	/// See: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
	static ref NUMS_H: secp256k1::PublicKey = secp256k1::PublicKey::from_str(
		"0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
	).unwrap();
}

/// Create a NUMS point from the given entropy.
fn nums(entropy: secp256k1::Scalar) -> secp256k1::PublicKey {
	NUMS_H.add_exp_tweak(&SECP, &entropy).expect("invalid NUMS entropy")
}

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("address", "work with addresses")
		.subcommand(cmd_create())
		.subcommand(cmd_inspect())
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	match matches.subcommand() {
		("create", Some(ref m)) => exec_create(&m),
		("inspect", Some(ref m)) => exec_inspect(&m),
		(_, _) => unreachable!("clap prints help"),
	};
}

fn cmd_create<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("create", "create addresses").args(&cmd::opts_networks()).args(&[
		cmd::opt_yaml(),
		cmd::opt("pubkey", "a public key in hex").takes_value(true).required(false),
		cmd::opt("script", "a script in hex").takes_value(true).required(false),
		cmd::opt(
			"nums-internal-key-h",
			"use the H NUMS key from BIP-341 for p2tr address when using --script",
		).takes_value(false).required(false),
		cmd::opt(
			"nums-internal-key",
			"NUMS internal pubkey to use with --script for p2tr",
		).takes_value(true).required(false),
		cmd::opt(
			"nums-internal-key-entropy",
			"entropy to use to create NUMS internal pubkey to use with --script for p2tr\n\
			the zero scalar is used when left empty, this means the BIP-341 NUMS point H is used",
		).takes_value(true).required(false),
	])
}

fn exec_create<'a>(matches: &clap::ArgMatches<'a>) {
	let network = cmd::network(matches);

	if let Some(pubkey_hex) = matches.value_of("pubkey") {
		let pubkey = pubkey_hex.parse::<PublicKey>().expect("invalid pubkey");
		let addr = hal::address::Addresses::from_pubkey(&pubkey, network);
		cmd::print_output(matches, &addr)
	} else if let Some(script_hex) = matches.value_of("script") {
		let script_bytes = hex::decode(script_hex).expect("invalid script hex");
		let script = script_bytes.into();

		let mut ret = hal::address::Addresses::from_script(&script, network);

		// If the user provided NUMS information we can add a p2tr address.
		if util::more_than_one(&[
			matches.is_present("nums-internal-key-h"),
			matches.is_present("nums-internal-key"),
			matches.is_present("nums-internal-key-entropy"),
		]) {
			println!("Use only either nums-h, nums-internal-key or nums-internal-key-entropy.\n");
			cmd_create().print_help().unwrap();
			std::process::exit(1);
		}
		let nums: Option<secp256k1::PublicKey> = if matches.is_present("nums-internal-key-h") {
			Some(*NUMS_H)
		} else if let Some(int) = matches.value_of("nums-internal-key") {
			Some(int.parse().expect("invalid nums internal key"))
		} else if let Some(ent) = matches.value_of("nums-internal-key-entropy") {
			let scalar = <[u8; 32]>::from_hex(ent)
				.expect("invalid entropy format: must be 32-byte hex");
			Some(nums(secp256k1::Scalar::from_be_bytes(scalar).expect("invalid NUMS entropy")))
		} else {
			None
		};
		if let Some(pk) = nums {
			let spk = script.to_v1_p2tr(&SECP, pk.into());
			ret.p2tr = Some(Address::from_script(&spk, network).unwrap());
		}

		cmd::print_output(matches, &ret)
	} else {
		cmd_create().print_help().unwrap();
		std::process::exit(1);
	}
}

fn cmd_inspect<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("inspect", "inspect addresses")
		.args(&[cmd::opt_yaml(), cmd::arg("address", "the address").required(true)])
}

fn exec_inspect<'a>(matches: &clap::ArgMatches<'a>) {
	let address_str = matches.value_of("address").expect("no address provided");
	let address: Address = address_str.parse().expect("invalid address format");
	let script_pk = address.script_pubkey();

	let mut info = hal::address::AddressInfo {
		network: address.network,
		script_pub_key: hal::tx::OutputScriptInfo {
			hex: Some(script_pk.to_bytes().into()),
			asm: Some(script_pk.asm()),
			address: None,
			type_: None,
		},
		type_: None,
		pubkey_hash: None,
		script_hash: None,
		witness_pubkey_hash: None,
		witness_script_hash: None,
		witness_program_version: None,
	};

	use bitcoin::util::address::Payload;
	match address.payload {
		Payload::PubkeyHash(pkh) => {
			info.type_ = Some("p2pkh".to_owned());
			info.pubkey_hash = Some(pkh);
		}
		Payload::ScriptHash(sh) => {
			info.type_ = Some("p2sh".to_owned());
			info.script_hash = Some(sh);
		}
		Payload::WitnessProgram {
			version,
			program,
		} => {
			let version = version.to_num() as usize;
			info.witness_program_version = Some(version);

			if version == 0 {
				if program.len() == 20 {
					info.type_ = Some("p2wpkh".to_owned());
					info.witness_pubkey_hash =
						Some(WPubkeyHash::from_slice(&program).expect("size 20"));
				} else if program.len() == 32 {
					info.type_ = Some("p2wsh".to_owned());
					info.witness_script_hash =
						Some(WScriptHash::from_slice(&program).expect("size 32"));
				} else {
					info.type_ = Some("invalid-witness-program".to_owned());
				}
			} else {
				info.type_ = Some("unknown-witness-program-version".to_owned());
			}
		}
	}

	cmd::print_output(matches, &info)
}
