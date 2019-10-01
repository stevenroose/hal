use std::str::FromStr;

use bitcoin::secp256k1;
use bitcoin::util::bip32;
use bitcoin::{Address, PublicKey};
use clap;

use cmd;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("bip32", "BIP-32 key derivation")
		.subcommand(cmd_derive())
		.subcommand(cmd_inspect())
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	match matches.subcommand() {
		("derive", Some(ref m)) => exec_derive(&m),
		("inspect", Some(ref m)) => exec_inspect(&m),
		(_, _) => unreachable!("clap prints help"),
	};
}

fn cmd_derive<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("derive", "derive keys from an extended key").arg(cmd::opt_yaml()).args(&[
		cmd::arg("ext-key", "extended public or private key").required(true),
		cmd::arg("derivation-path", "the derivation path").required(true),
	])
}

fn exec_derive<'a>(matches: &clap::ArgMatches<'a>) {
	let path_str = matches.value_of("derivation-path").unwrap();
	let path: bip32::DerivationPath = path_str.parse().expect("error parsing derivation path");

	let key_str = matches.value_of("ext-key").unwrap();
	let master_fingerprint;
	let mut secret_key = None;

	let secp = secp256k1::Secp256k1::new();
	let derived = match bip32::ExtendedPrivKey::from_str(&key_str) {
		Ok(ext_priv) => {
			let derived_priv = ext_priv.derive_priv(&secp, &path).expect("derivation error");
			master_fingerprint = ext_priv.fingerprint(&secp);
			secret_key = Some(derived_priv.private_key.to_wif());
			bip32::ExtendedPubKey::from_private(&secp, &derived_priv)
		}
		Err(_) => {
			let ext_pub: bip32::ExtendedPubKey = key_str.parse().expect("invalid extended key");
			master_fingerprint = ext_pub.fingerprint();
			ext_pub.derive_pub(&secp, &path).expect("derivation error")
		}
	};

	let info = hal::bip32::DerivationInfo {
		network: derived.network,
		master_fingerprint: Some(master_fingerprint[..].into()),
		path: Some(path_str.to_owned()),
		chain_code: derived.chain_code.to_bytes()[..].into(),
		identifier: derived.identifier()[..].into(),
		fingerprint: derived.fingerprint()[..].into(),
		public_key: {
			//TODO(stevenroose) key.serialize()
			let mut buf = Vec::new();
			derived.public_key.write_into(&mut buf);
			buf.into()
		},
		secret_key: secret_key.map(|k| k[..].into()),
		parent_fingerprint: derived.fingerprint()[..].into(),
		address_p2pkh: Address::p2pkh(&derived.public_key, derived.network),
		address_p2wpkh: Address::p2wpkh(&derived.public_key, derived.network),
		address_p2shwpkh: Address::p2shwpkh(&derived.public_key, derived.network),
	};

	cmd::print_output(matches, &info)
}

fn cmd_inspect<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("inspect", "inspect a BIP-32 xpub or xpriv").args(&cmd::opts_networks()).args(
		&[cmd::opt_yaml(), cmd::arg("ext-key", "extended public or private key").required(true)],
	)
}

fn exec_inspect<'a>(matches: &clap::ArgMatches<'a>) {
	let key_str = matches.value_of("ext-key").unwrap();

	let secp = bitcoin::secp256k1::Secp256k1::new();
	let info = match bip32::ExtendedPrivKey::from_str(&key_str) {
		Ok(ext) => {
			let public_key = PublicKey::from_private_key(&secp, &ext.private_key);
			hal::bip32::DerivationInfo {
				network: ext.network,
				master_fingerprint: None,
				chain_code: ext.chain_code.to_bytes()[..].into(),
				identifier: ext.identifier(&secp)[..].into(),
				fingerprint: ext.fingerprint(&secp)[..].into(),
				public_key: {
					//TODO(stevenroose) key.serialize()
					let mut buf = Vec::new();
					public_key.write_into(&mut buf);
					buf.into()
				},
				secret_key: Some(ext.private_key.to_wif()),
				parent_fingerprint: ext.fingerprint(&secp)[..].into(),
				address_p2pkh: Address::p2pkh(&public_key, ext.network),
				address_p2wpkh: Address::p2wpkh(&public_key, ext.network),
				address_p2shwpkh: Address::p2shwpkh(&public_key, ext.network),
				path: None,
			}
		}
		Err(_) => {
			let ext: bip32::ExtendedPubKey = key_str.parse().expect("invalid extended key");
			hal::bip32::DerivationInfo {
				network: ext.network,
				master_fingerprint: None,
				chain_code: ext.chain_code.to_bytes()[..].into(),
				identifier: ext.identifier()[..].into(),
				fingerprint: ext.fingerprint()[..].into(),
				public_key: {
					//TODO(stevenroose) key.serialize()
					let mut buf = Vec::new();
					ext.public_key.write_into(&mut buf);
					buf.into()
				},
				secret_key: None,
				parent_fingerprint: ext.fingerprint()[..].into(),
				address_p2pkh: Address::p2pkh(&ext.public_key, ext.network),
				address_p2wpkh: Address::p2wpkh(&ext.public_key, ext.network),
				address_p2shwpkh: Address::p2shwpkh(&ext.public_key, ext.network),
				path: None,
			}
		}
	};

	cmd::print_output(matches, &info)
}
