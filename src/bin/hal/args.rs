
use std::borrow::Borrow;
use std::str::FromStr;

use bitcoin::consensus::encode::Decodable;
use bitcoin::Network;
use secp256k1::{self, XOnlyPublicKey};

use crate::exit;

/// Construct a new boolean command flag.
pub fn flag<'a>(name: &'a str, help: &'a str) -> clap::Arg<'a, 'a> {
	clap::Arg::with_name(name).long(name).help(help).takes_value(false).required(false)
}

/// Construct a new command option.
pub fn opt<'a>(name: &'a str, help: &'a str) -> clap::Arg<'a, 'a> {
	clap::Arg::with_name(name).long(name).help(help).takes_value(true).required(false)
}

/// Construct a new positional argument.
pub fn arg<'a>(name: &'a str, help: &'a str) -> clap::Arg<'a, 'a> {
	clap::Arg::with_name(name).help(help).takes_value(true)
}

/// Global options for network selection.
pub fn opts_networks() -> Vec<clap::Arg<'static, 'static>> {
	vec![
		flag("testnet", "run in testnet mode")
			.short("t")
			.required(false)
			.global(true),
		flag("signet", "run in signet mode")
			.required(false)
			.global(true),
		flag("regtest", "run in regtest mode")
			.required(false)
			.global(true),
	]
}

/// Global option for changing output format to YAML.
pub fn opt_yaml() -> clap::Arg<'static, 'static> {
	flag("yaml", "print output in YAML instead of JSON")
		.short("y")
		.required(false)
		.global(true)
}

pub trait ArgMatchesExt<'a>: Borrow<clap::ArgMatches<'a>> {
	fn verbose(&self) -> bool {
		self.borrow().is_present("verbose")
	}

	fn network(&self) -> bitcoin::Network {
		if self.borrow().is_present("testnet") {
			Network::Testnet
		} else if self.borrow().is_present("signet") {
			Network::Signet
		} else if self.borrow().is_present("regtest") {
			Network::Regtest
		} else {
			Network::Bitcoin
		}
	}

	fn privkey(&self, key: &str) -> Option<bitcoin::PrivateKey> {
		self.borrow().value_of(key).map(|s| {
			bitcoin::PrivateKey::from_str(&s).unwrap_or_else(|_| {
				let key = secp256k1::SecretKey::from_str(&s).unwrap_or_else(|_| {
					exit!("invalid WIF/hex private key provided for argument '{}'", key);
				});
				bitcoin::PrivateKey {
					compressed: true,
					network: self.network(),
					inner: key,
				}
			})
		})
	}

	fn need_privkey(&self, key: &str) -> bitcoin::PrivateKey {
		self.privkey(key).unwrap_or_else(|| {
			exit!("expected a private key for argument '{}'", key);
		})
	}

	fn pubkey(&self, key: &str) -> Option<bitcoin::PublicKey> {
		self.borrow().value_of(key).map(|s| {
			bitcoin::PublicKey::from_str(&s).unwrap_or_else(|_| {
				exit!("invalid public key provided for argument '{}'", key);
			})
		})
	}

	fn need_pubkey(&self, key: &str) -> bitcoin::PublicKey {
		self.pubkey(key).unwrap_or_else(|| {
			exit!("expected a public key for argument '{}'", key);
		})
	}

	fn xonly_pubkey(&self, key: &str) -> Option<XOnlyPublicKey> {
		self.borrow().value_of(key).map(|s| {
			XOnlyPublicKey::from_str(&s).or_else(|_| {
				bitcoin::PublicKey::from_str(&s).map(|pk| pk.inner.x_only_public_key().0)
			}).unwrap_or_else(|_| {
				exit!("invalid public key provided for argument '{}'", key);
			})
		})
	}

	fn need_xonly_pubkey(&self, key: &str) -> XOnlyPublicKey {
		self.xonly_pubkey(key).unwrap_or_else(|| {
			exit!("expected a public key for argument '{}'", key);
		})
	}

	fn hex_consensus<T: Decodable>(&self, key: &str) -> Option<Result<T, String>> {
		self.borrow().value_of(key).map(|s| -> Result<T, String> {
			let mut hex = bitcoin::hashes::hex::HexIterator::new(s)
				.map_err(|e| format!("invalid hex: {}", e))?;
			let ret = Decodable::consensus_decode(&mut hex)
				.map_err(|e| format!("invalid format: {}", e))?;
			Ok(ret)
		})
	}

	fn out_yaml(&self) -> bool {
		self.borrow().is_present("yaml")
	}

	fn print_output<T: serde::Serialize>(&self, out: &T) {
		if self.out_yaml() {
			serde_yaml::to_writer(::std::io::stdout(), &out).unwrap();
		} else {
			serde_json::to_writer_pretty(::std::io::stdout(), &out).unwrap();
		}
	}
}

impl<'a> ArgMatchesExt<'a> for clap::ArgMatches<'a> {}
