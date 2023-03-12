use bip39lib::{Language, Mnemonic};
use bitcoin::{secp256k1, util::bip32, Network};
use serde::{Deserialize, Serialize};

use crate::{GetInfo, HexBytes};

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
	pub bip32_xpriv: bip32::ExtendedPrivKey,
	pub bip32_xpub: bip32::ExtendedPubKey,
}

impl GetInfo<SeedInfo> for [u8; 64] {
	fn get_info(&self, network: Network) -> SeedInfo {
		let xpriv = bip32::ExtendedPrivKey::new_master(network, &self[..]).unwrap();
		let xpub =
			bip32::ExtendedPubKey::from_priv(&secp256k1::Secp256k1::signing_only(), &xpriv);
		SeedInfo {
			seed: self.to_vec().into(),
			bip32_xpriv: xpriv,
			bip32_xpub: xpub,
		}
	}
}
