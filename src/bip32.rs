use bitcoin::Network;
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct DerivationInfo {
	pub network: Network,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub master_fingerprint: Option<::HexBytes>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub path: Option<String>,
	pub chain_code: ::HexBytes,
	pub identifier: ::HexBytes,
	pub fingerprint: ::HexBytes,
	pub public_key: ::HexBytes,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub secret_key: Option<String>,
	pub parent_fingerprint: ::HexBytes,
	pub addresses: ::address::Addresses,
}
