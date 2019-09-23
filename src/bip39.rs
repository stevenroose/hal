use bip39lib::{Language, Mnemonic, Seed};
use bitcoin::{secp256k1, util::bip32, Network};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct MnemonicInfo {
	pub mnemonic: String,
	pub entropy: ::HexBytes,
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
		let entropy: Vec<u8> = mnemonic.entropy().into();
		MnemonicInfo {
			mnemonic: mnemonic.phrase().to_owned(),
			entropy_bits: entropy.len() * 8,
			entropy: entropy.into(),
			language: match mnemonic.language() {
				Language::English => "english",
				Language::ChineseSimplified => "simplified-chinese",
				Language::ChineseTraditional => "traditional-chinese",
				Language::French => "french",
				Language::Italian => "italian",
				Language::Japanese => "japanese",
				Language::Korean => "korean",
				Language::Spanish => "spanish",
			},
			passphrase: passphrase.to_owned(),
			seed: ::GetInfo::get_info(&bip39::Seed::new(&mnemonic, passphrase), network),
		}
	}
}

impl ::GetInfo<MnemonicInfo> for Mnemonic {
	fn get_info(&self, network: Network) -> MnemonicInfo {
		MnemonicInfo::from_mnemonic_with_passphrase(self, "", network)
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct SeedInfo {
	pub seed: ::HexBytes,
	pub bip32_xpriv: bip32::ExtendedPrivKey,
	pub bip32_xpub: bip32::ExtendedPubKey,
}

impl ::GetInfo<SeedInfo> for Seed {
	fn get_info(&self, network: Network) -> SeedInfo {
		let xpriv = bip32::ExtendedPrivKey::new_master(network, self.as_bytes()).unwrap();
		let xpub =
			bip32::ExtendedPubKey::from_private(&secp256k1::Secp256k1::signing_only(), &xpriv);
		SeedInfo {
			seed: self.as_bytes().into(),
			bip32_xpriv: xpriv,
			bip32_xpub: xpub,
		}
	}
}
