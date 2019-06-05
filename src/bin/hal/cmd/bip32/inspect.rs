use std::str::FromStr;

use bitcoin::util::bip32;
use bitcoin::{Address, PublicKey};
use clap;

use cmd;
use hal;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("inspect", "inspect a BIP-32 xpub or xpriv").args(&cmd::opts_networks()).args(
		&[cmd::opt_yaml(), cmd::arg("ext-key", "extended public or private key").required(true)],
	)
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	let key_str = matches.value_of("ext-key").unwrap();

	let secp = secp256k1::Secp256k1::new();
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
