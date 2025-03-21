
use bitcoin::{
	address, Address, Network, Script, PubkeyHash, ScriptHash, WPubkeyHash, WScriptHash,
};
use secp256k1::XOnlyPublicKey;
use serde::{Deserialize, Serialize};

use crate::SECP;
use crate::tx;

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct AddressInfo {
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
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize)]
pub struct Addresses {
	#[serde(skip_serializing_if = "Option::is_none")]
	pub p2pkh: Option<Address<address::NetworkUnchecked>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub p2wpkh: Option<Address<address::NetworkUnchecked>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub p2shwpkh: Option<Address<address::NetworkUnchecked>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub p2sh: Option<Address<address::NetworkUnchecked>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub p2wsh: Option<Address<address::NetworkUnchecked>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub p2shwsh: Option<Address<address::NetworkUnchecked>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub p2tr: Option<Address<address::NetworkUnchecked>>,
}

impl Addresses {
	pub fn from_pubkey(pubkey: &bitcoin::PublicKey, network: Network) -> Addresses {
		Addresses {
			p2pkh: Some(Address::p2pkh(pubkey, network).as_unchecked().clone()),
			p2wpkh: if pubkey.compressed {
				let pk = bitcoin::CompressedPublicKey(pubkey.inner);
				Some(Address::p2wpkh(&pk, network).as_unchecked().clone())
			} else {
				None
			},
			p2shwpkh: if pubkey.compressed {
				let pk = bitcoin::CompressedPublicKey(pubkey.inner);
				Some(Address::p2shwpkh(&pk, network).as_unchecked().clone())
			} else {
				None
			},
			p2tr: if pubkey.compressed {
				let pk = pubkey.inner.into();
				Some(Address::p2tr(&SECP, pk, None, network).as_unchecked().clone())
			} else {
				None
			},
			..Default::default()
		}
	}

	pub fn from_xonly_pubkey(pubkey: XOnlyPublicKey, network: Network) -> Addresses {
		Addresses {
			p2tr: Some(Address::p2tr(&SECP, pubkey, None, network).as_unchecked().clone()),
			..Default::default()
		}
	}

	pub fn from_script(script: &Script, network: Network) -> Addresses {
		Addresses {
			p2sh: Address::p2sh(&script, network).ok().map(|a| a.as_unchecked().clone()),
			p2wsh: Some(Address::p2wsh(&script, network).as_unchecked().clone()),
			p2shwsh: Some(Address::p2shwsh(&script, network).as_unchecked().clone()),
			// NB to make a p2tr here we need a NUMS internal key and it's
			// probably not safe to pick one ourselves. AFAIK there is no
			// standard NUMS point for this purpose.
			// (Though BIP341 suggests one..)
			..Default::default()
		}
	}
}
