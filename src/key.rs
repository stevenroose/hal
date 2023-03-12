use bitcoin::{Network, PrivateKey, PublicKey};
use serde::{Deserialize, Serialize};

use crate::{address, GetInfo, HexBytes};

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct KeyInfo {
	pub raw_private_key: HexBytes,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub wif_private_key: Option<PrivateKey>,
	pub public_key: PublicKey,
	pub uncompressed_public_key: PublicKey,
	pub addresses: address::Addresses,
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
pub struct SignatureInfo {
	pub der: HexBytes,
	pub compact: HexBytes,
}

