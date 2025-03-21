
use bitcoin::{bip32, NetworkKind};
use serde::{Deserialize, Serialize};

use crate::address;

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct DerivationInfo {
	#[serde(with = "crate::serde_utils::network_kind")]
	pub network: NetworkKind,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub master_fingerprint: Option<bip32::Fingerprint>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub path: Option<bip32::DerivationPath>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub xpriv: Option<bip32::Xpriv>,
	pub xpub: bip32::Xpub,
	pub chain_code: bip32::ChainCode,
	pub identifier: bip32::XKeyIdentifier,
	pub fingerprint: bip32::Fingerprint,
	pub public_key: bitcoin::secp256k1::PublicKey,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub private_key: Option<bitcoin::secp256k1::SecretKey>,
	pub addresses: address::Addresses,
}
