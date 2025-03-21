
use bitcoin::{secp256k1, Network, PrivateKey, PublicKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};

use crate::{SECP, address, GetInfo, HexBytes};

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct KeyInfo {
	pub raw_private_key: HexBytes,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub wif_private_key: Option<PrivateKey>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub uncompressed_wif_private_key: Option<PrivateKey>,
	pub public_key: PublicKey,
	pub xonly_public_key: XOnlyPublicKey,
	pub uncompressed_public_key: PublicKey,
	pub addresses: address::Addresses,
}

impl GetInfo<KeyInfo> for PrivateKey {
	fn get_info(&self, network: Network) -> KeyInfo {
		let pubkey = self.public_key(&SECP);
		let mut compressed_wif_privkey = *self;
		compressed_wif_privkey.compressed = true;
		let mut uncompressed_wif_privkey = *self;
		uncompressed_wif_privkey.compressed = false;
		KeyInfo {
			raw_private_key: (&self.inner[..]).into(),
			wif_private_key: Some(compressed_wif_privkey),
			uncompressed_wif_private_key: Some(uncompressed_wif_privkey),
			public_key: pubkey,
			xonly_public_key: pubkey.inner.into(),
			uncompressed_public_key: {
				let mut uncompressed = pubkey.clone();
				uncompressed.compressed = false;
				uncompressed
			},
			addresses: address::Addresses::from_pubkey(&pubkey, network),
		}
	}
}

impl GetInfo<KeyInfo> for secp256k1::SecretKey {
	fn get_info(&self, network: Network) -> KeyInfo {
		let pubkey = secp256k1::PublicKey::from_secret_key(&SECP, self);
		let btc_pubkey = PublicKey {
			compressed: true,
			inner: pubkey.clone(),
		};
		KeyInfo {
			raw_private_key: self[..].into(),
			wif_private_key: None,
			uncompressed_wif_private_key: None,
			public_key: btc_pubkey,
			xonly_public_key: pubkey.into(),
			uncompressed_public_key: PublicKey {
				compressed: false,
				inner: pubkey,
			},
			addresses: address::Addresses::from_pubkey(&btc_pubkey, network),
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct PublicKeyInfo {
	pub public_key: PublicKey,
	pub uncompressed_public_key: PublicKey,
	pub addresses: address::Addresses,
}

impl GetInfo<PublicKeyInfo> for PublicKey {
	fn get_info(&self, network: Network) -> PublicKeyInfo {
		PublicKeyInfo {
			public_key: {
				let mut key = self.clone();
				key.compressed = true;
				key
			},
			uncompressed_public_key: {
				let mut key = self.clone();
				key.compressed = false;
				key
			},
			addresses: address::Addresses::from_pubkey(&self, network),
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct EcdsaSignatureInfo {
	pub der: HexBytes,
	pub compact: HexBytes,
}

impl GetInfo<EcdsaSignatureInfo> for secp256k1::ecdsa::Signature {
	fn get_info(&self, _network: Network) -> EcdsaSignatureInfo {
		EcdsaSignatureInfo {
			der: self.serialize_der().as_ref().into(),
			compact: self.serialize_compact().to_vec().into(),
		}
	}
}
