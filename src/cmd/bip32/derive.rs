use bitcoin::util::bip32;
use bitcoin::{Address, Privkey};
use secp256k1;

use std::str::FromStr;

use cmd;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	clap::SubCommand::with_name("derive")
		.about("derive keys from an extended key")
		.arg(cmd::arg_yaml())
		.args(&[
			clap::Arg::with_name("ext-key")
				.help("extended public or private key")
				.takes_value(true)
				.required(true),
			clap::Arg::with_name("derivation-path")
				.help("the derivation path")
				.takes_value(true)
				.required(true),
		])
}

//TODO(stevenroose) replace once PR is merged:
// https://github.com/rust-bitcoin/rust-bitcoin/pull/185
fn parse_child_number(inp: &str) -> bip32::ChildNumber {
	match inp.chars().last().map_or(false, |l| l == '\'' || l == 'h') {
		true => bip32::ChildNumber::from_hardened_idx(
			inp[0..inp.len() - 1].parse().expect("invalid derivation path format"),
		),
		false => bip32::ChildNumber::from_normal_idx(
			inp.parse().expect("invalid derivation path format"),
		),
	}
}
fn parse_derivation_path(path: &str) -> Vec<bip32::ChildNumber> {
	let mut parts = path.split("/");
	// First parts must be `m`.
	if parts.next().unwrap() != "m" {
		panic!("invalid derivation path format");
	}

	// Empty parts are a format error.
	if parts.clone().any(|p| p.len() == 0) {
		panic!("invalid derivation path format");
	}

	parts.map(parse_child_number).collect()
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	let path_str = matches.value_of("derivation-path").unwrap();
	//let path = bip32::parse_derivation_path(path_str).expect("error parsing derivation path");
	let path = parse_derivation_path(path_str);

	let key_str = matches.value_of("ext-key").unwrap();
	let master_fingerprint;
	let mut secret_key = None;

	let secp = secp256k1::Secp256k1::new();
	let derived = match bip32::ExtendedPrivKey::from_str(&key_str) {
		Ok(ext_priv) => {
			let derived_priv = ext_priv.derive_priv(&secp, &path).expect("derivation error");

			master_fingerprint = ext_priv.fingerprint(&secp);
			//TODO(stevenroose) change this after Carl's PR
			let btcpriv =
				Privkey::from_secret_key(derived_priv.secret_key, true, derived_priv.network);
			secret_key = Some(btcpriv.to_wif());

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
		master_fingerprint: master_fingerprint[..].into(),
		path: path_str.to_owned(),
		chain_code: derived.chain_code.to_bytes()[..].into(),
		identifier: derived.identifier()[..].into(),
		fingerprint: derived.fingerprint()[..].into(),
		public_key: derived.public_key.serialize()[..].into(),
		secret_key: secret_key.map(|k| k[..].into()),
		parent_fingerprint: derived.fingerprint()[..].into(),
		address_p2pkh: Address::p2pkh(&derived.public_key, derived.network),
		address_p2wpkh: Address::p2wpkh(&derived.public_key, derived.network),
		address_p2shwpkh: Address::p2shwpkh(&derived.public_key, derived.network),
	};

	cmd::print_output(matches, &info)
}
