use bitcoin::secp256k1;
use bitcoin::util::bip32;
use bitcoin::Address;

use std::str::FromStr;

use cmd;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("derive", "derive keys from an extended key").arg(cmd::opt_yaml()).args(&[
		cmd::arg("ext-key", "extended public or private key").required(true),
		cmd::arg("derivation-path", "the derivation path").required(true),
	])
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
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
