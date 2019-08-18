use bitcoin::Network;
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct AddressInfo {
	pub network: Network,
	#[serde(rename = "type")]
	pub type_: Option<String>,
	pub script_pub_key: ::tx::OutputScriptInfo,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub witness_program_version: Option<usize>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub pubkey_hash: Option<::HexBytes>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub script_hash: Option<::HexBytes>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize)]
pub struct CreatedAddresses {
	#[serde(skip_serializing_if = "Option::is_none")]
	pub p2pkh: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub p2wpkh: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub p2shwpkh: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub p2sh: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub p2wsh: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub p2shwsh: Option<String>,
}
