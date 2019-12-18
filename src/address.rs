use bitcoin::{Address, Network, PublicKey, Script};
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
pub struct Addresses {
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

impl Addresses {
	pub fn from_pubkey(pubkey: &PublicKey, network: Network) -> Addresses {
		Addresses {
			p2pkh: Some(Address::p2pkh(pubkey, network).to_string()),
			p2wpkh: Some(Address::p2wpkh(pubkey, network).to_string()),
			p2shwpkh: Some(Address::p2shwpkh(pubkey, network).to_string()),
			..Default::default()
		}
	}

	pub fn from_script(script: &Script, network: Network) -> Addresses {
		Addresses {
			p2sh: Some(Address::p2sh(&script, network).to_string()),
			p2wsh: Some(Address::p2wsh(&script, network).to_string()),
			p2shwsh: Some(Address::p2shwsh(&script, network).to_string()),
			..Default::default()
		}
	}
}
