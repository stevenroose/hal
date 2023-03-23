use std::str::FromStr;

use bitcoin::secp256k1;
use bitcoin::util::bip32;
use clap;

use crate::cmd;

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

	let secp = secp256k1::Secp256k1::new();

	let master_fingerprint;
	let mut derived_xpriv = None;
	let derived_xpub = match bip32::ExtendedPrivKey::from_str(&key_str) {
		Ok(ext_priv) => {
			derived_xpriv = Some(ext_priv.derive_priv(&secp, &path).expect("derivation error"));
			master_fingerprint = ext_priv.fingerprint(&secp);
			bip32::ExtendedPubKey::from_priv(&secp, derived_xpriv.as_ref().unwrap())
		}
		Err(_) => {
			let ext_pub: bip32::ExtendedPubKey = key_str.parse().expect("invalid extended key");
			master_fingerprint = ext_pub.fingerprint();
			ext_pub.derive_pub(&secp, &path).expect("derivation error")
		}
	};

	let info = hal::bip32::DerivationInfo {
		network: derived_xpub.network,
		master_fingerprint: Some(master_fingerprint),
		path: Some(path),
		xpriv: derived_xpriv,
		xpub: derived_xpub,
		chain_code: derived_xpub.chain_code,
		identifier: derived_xpub.identifier(),
		fingerprint: derived_xpub.fingerprint(),
		public_key: derived_xpub.public_key,
		private_key: derived_xpriv.map(|x| x.private_key),
		addresses: hal::address::Addresses::from_pubkey(
			&bitcoin::PublicKey::new(derived_xpub.public_key), derived_xpub.network,
		),
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

	let secp = bitcoin::secp256k1::Secp256k1::signing_only();

	let mut xpriv = None;

	let xpub = match bip32::ExtendedPrivKey::from_str(&key_str) {
		Ok(ext_priv) => {
			xpriv = Some(ext_priv);
			bip32::ExtendedPubKey::from_priv(&secp, xpriv.as_ref().unwrap())
		}
		Err(_) => key_str.parse().expect("invalid extended key"),
	};

	let info = hal::bip32::DerivationInfo {
		network: xpub.network,
		master_fingerprint: None,
		path: None,
		xpriv: xpriv,
		xpub: xpub,
		chain_code: xpub.chain_code,
		identifier: xpub.identifier(),
		fingerprint: xpub.fingerprint(),
		public_key: xpub.public_key,
		private_key: xpriv.map(|x| x.private_key),
		addresses: hal::address::Addresses::from_pubkey(
			&bitcoin::PublicKey::new(xpub.public_key), xpub.network,
		),
	};

	cmd::print_output(matches, &info)
}
