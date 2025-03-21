
use std::borrow::Cow;

use bip39lib::{Language, Mnemonic};
use bitcoin::Network;
use bitcoin::bip32;
use serde::{Deserialize, Serialize};

use crate::{SECP, GetInfo, HexBytes};

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct MnemonicInfo {
	pub mnemonic: String,
	pub entropy: HexBytes,
	pub entropy_bits: usize,
	pub language: &'static str,
	pub passphrase: String,
	pub seed: SeedInfo,
}

impl MnemonicInfo {
	pub fn from_mnemonic_with_passphrase(
		mnemonic: &Mnemonic,
		passphrase: &str,
		network: Network,
	) -> MnemonicInfo {
		let entropy: Vec<u8> = mnemonic.to_entropy().into();
		MnemonicInfo {
			mnemonic: mnemonic.to_string(),
			entropy_bits: entropy.len() * 8,
			entropy: entropy.into(),
			language: match mnemonic.language() {
				Language::English => "english",
				Language::Czech => "czech",
				Language::French => "french",
				Language::Italian => "italian",
				Language::Japanese => "japanese",
				Language::Korean => "korean",
				Language::Portuguese => "portuguese",
				Language::Spanish => "spanish",
				Language::SimplifiedChinese => "simplified-chinese",
				Language::TraditionalChinese => "traditional-chinese",
			},
			passphrase: passphrase.to_owned(),
			seed: GetInfo::get_info(&mnemonic.to_seed(passphrase), network),
		}
	}
}

impl GetInfo<MnemonicInfo> for Mnemonic {
	fn get_info(&self, network: Network) -> MnemonicInfo {
		MnemonicInfo::from_mnemonic_with_passphrase(self, "", network)
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct SeedInfo {
	pub seed: HexBytes,
	pub bip32_xpriv: bip32::Xpriv,
	pub bip32_xpub: bip32::Xpub,
}

impl GetInfo<SeedInfo> for [u8; 64] {
	fn get_info(&self, network: Network) -> SeedInfo {
		let xpriv = bip32::Xpriv::new_master(network, &self[..]).unwrap();
		let xpub =
			bip32::Xpub::from_priv(&SECP, &xpriv);
		SeedInfo {
			seed: self.to_vec().into(),
			bip32_xpriv: xpriv,
			bip32_xpub: xpub,
		}
	}
}

/// Parse a BIP-39 language from string.
///
/// Supported formats are (case-insensitive):
/// - full name in English
/// - full name in English with hyphen instead of space
/// - ISO 639-1 code
///   - except for Simplified Chinese: "sc" or "zhs"
///   - except for Traditional Chinese: "tc" or "zht"
pub fn parse_language(s: &str) -> Option<Language> {
	if !s.is_ascii() {
		return None;
	}

	let s = if s.chars().all(|c| c.is_lowercase()) {
		Cow::Borrowed(s)
	} else {
		Cow::Owned(s.to_lowercase())
	};
	let ret = match s.as_ref() {
		"en" | "english" => Language::English,
		"sc" | "zhs" | "simplified chinese" | "simplified-chinese"
			| "simplifiedchinese" => Language::SimplifiedChinese,
		"tc" | "zht" | "traditional chinese"| "traditional-chinese"
			| "traditionalchinese" => Language::TraditionalChinese,
		"cs" | "czech" => Language::Czech,
		"fr" | "french" => Language::French,
		"it" | "italian" => Language::Italian,
		"ja" | "japanese" => Language::Japanese,
		"ko" | "korean" => Language::Korean,
		"pt" | "portuguese" => Language::Portuguese,
		"es" | "spanish" => Language::Spanish,
		_ => return None,
	};
	Some(ret)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_parse_language() {
		// a simple check all
		for l in Language::ALL {
			assert_eq!(Some(*l), parse_language(&l.to_string()), "lang: {}", l);
			assert_eq!(Some(*l), parse_language(&l.to_string().to_uppercase()), "lang: {}", l);
		}
	}
}
