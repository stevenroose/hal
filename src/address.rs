use bitcoin::address::NetworkUnchecked;
use bitcoin::{self, Address, Network, Script, PubkeyHash, ScriptHash, WPubkeyHash, WScriptHash};
use secp256k1::XOnlyPublicKey;
use serde::{Deserialize, Serialize};

use crate::SECP;
use crate::tx;

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct AddressInfo {
	pub network: Network,
	#[serde(rename = "type")]
	pub type_: Option<String>,
	pub script_pub_key: tx::OutputScriptInfo,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub witness_program_version: Option<usize>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub pubkey_hash: Option<PubkeyHash>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub script_hash: Option<ScriptHash>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub witness_pubkey_hash: Option<WPubkeyHash>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub witness_script_hash: Option<WScriptHash>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub taproot_output_key: Option<XOnlyPublicKey>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct Addresses {
	#[serde(skip_serializing_if = "Option::is_none")]
	pub p2pkh: Option<Address<NetworkUnchecked>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub p2wpkh: Option<Address<NetworkUnchecked>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub p2shwpkh: Option<Address<NetworkUnchecked>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub p2sh: Option<Address<NetworkUnchecked>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub p2wsh: Option<Address<NetworkUnchecked>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub p2shwsh: Option<Address<NetworkUnchecked>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub p2tr: Option<Address<NetworkUnchecked>>,
}

pub fn addr_unchecked(addr: Address) -> Address<NetworkUnchecked> {
	Address::new(addr.network, addr.payload)
}

impl Addresses {
	pub fn from_pubkey(pubkey: &bitcoin::PublicKey, network: Network) -> Addresses {
		Addresses {
			p2pkh: Some(addr_unchecked(Address::p2pkh(pubkey, network))),
			p2wpkh: Address::p2wpkh(pubkey, network).map(addr_unchecked).ok(),
			p2shwpkh: Address::p2shwpkh(pubkey, network).map(addr_unchecked).ok(),
			p2tr: Some(addr_unchecked(Address::p2tr(&SECP, pubkey.inner.into(), None, network))),
			..Default::default()
		}
	}

	pub fn from_script(script: &Script, network: Network) -> Addresses {
		Addresses {
			p2sh: Address::p2sh(&script, network).map(addr_unchecked).ok(),
			p2wsh: Some(addr_unchecked(Address::p2wsh(&script, network))),
			p2shwsh: Some(addr_unchecked(Address::p2shwsh(&script, network))),
			// NB to make a p2tr here we need a NUMS internal key and it's
			// probably not safe to pick one ourselves. AFAIK there is no
			// standard NUMS point for this purpose.
			// (Though BIP341 suggests one..)
			..Default::default()
		}
	}
}
