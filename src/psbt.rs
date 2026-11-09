use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use bitcoin::hashes::{hash160, ripemd160, sha256, sha256d};
use bitcoin::taproot::{self, TapLeafHash, TapNodeHash, TapTree};
use bitcoin::{bip32, sighash, psbt, Amount, Network, XOnlyPublicKey};

use crate::{tx, GetInfo, HexBytes};

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct HDPathInfo {
	pub master_fingerprint: bip32::Fingerprint,
	pub path: bip32::DerivationPath,
}

impl From<&bip32::KeySource> for HDPathInfo {
	fn from(source: &bip32::KeySource) -> HDPathInfo {
		HDPathInfo {
			master_fingerprint: source.0,
			path: source.1.clone(),
		}
	}
}

pub fn sighashtype_to_string(sht: psbt::PsbtSighashType) -> &'static str {
	if let Ok(t) = sht.ecdsa_hash_ty() {
		match t {
			sighash::EcdsaSighashType::All => "ALL",
			sighash::EcdsaSighashType::None => "NONE",
			sighash::EcdsaSighashType::Single => "SINGLE",
			sighash::EcdsaSighashType::AllPlusAnyoneCanPay => "ALL|ANYONECANPAY",
			sighash::EcdsaSighashType::NonePlusAnyoneCanPay => "NONE|ANYONECANPAY",
			sighash::EcdsaSighashType::SinglePlusAnyoneCanPay => "SINGLE|ANYONECANPAY",
		}
	} else if let Ok(t) = sht.taproot_hash_ty() {
		match t {
            sighash::TapSighashType::Default => "SIGHASH_DEFAULT",
            sighash::TapSighashType::All => "SIGHASH_ALL",
            sighash::TapSighashType::None => "SIGHASH_NONE",
            sighash::TapSighashType::Single => "SIGHASH_SINGLE",
            sighash::TapSighashType::AllPlusAnyoneCanPay => "SIGHASH_ALL|SIGHASH_ANYONECANPAY",
            sighash::TapSighashType::NonePlusAnyoneCanPay => "SIGHASH_NONE|SIGHASH_ANYONECANPAY",
            sighash::TapSighashType::SinglePlusAnyoneCanPay => "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY",
		}
	} else {
		unreachable!();
	}
}

pub fn sighashtype_values() -> &'static [&'static str] {
	&["ALL", "NONE", "SINGLE", "ALL|ANYONECANPAY", "NONE|ANYONECANPAY", "SINGLE|ANYONECANPAY"]
}

pub fn ecdsa_sighashtype_from_string(sht: &str) -> Result<psbt::PsbtSighashType, &'static str> {
	lazy_static! {
		static ref ERR: &'static str = Box::leak(format!(
			"invalid ecdsa SIGHASH type value -- possible values: {:?}", &sighashtype_values(),
		).into_boxed_str());
	}

	use bitcoin::EcdsaSighashType::*;
	let ecdsa_sighash = match sht {
		"ALL" => All,
		"NONE" => None,
		"SINGLE" => Single,
		"ALL|ANYONECANPAY" => AllPlusAnyoneCanPay,
		"NONE|ANYONECANPAY" => NonePlusAnyoneCanPay,
		"SINGLE|ANYONECANPAY" => SinglePlusAnyoneCanPay,
		_ => return Err(&ERR),
	};
	Ok(psbt::PsbtSighashType::from(ecdsa_sighash))
}

/// A proprietary key-value pair (BIP-174 type 0xFC).
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct ProprietaryInfo {
	pub prefix: HexBytes,
	pub subtype: u8,
	pub key: HexBytes,
	pub value: HexBytes,
}

fn proprietary_info(
	map: &std::collections::BTreeMap<psbt::raw::ProprietaryKey, Vec<u8>>,
) -> Vec<ProprietaryInfo> {
	map.iter().map(|(k, v)| ProprietaryInfo {
		prefix: k.prefix.clone().into(),
		subtype: k.subtype,
		key: k.key.clone().into(),
		value: v.clone().into(),
	}).collect()
}

/// A key-value pair of a type unknown to this version of the library.
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct UnknownInfo {
	#[serde(rename = "type")]
	pub type_: u8,
	pub key: HexBytes,
	pub value: HexBytes,
}

fn unknown_info(map: &std::collections::BTreeMap<psbt::raw::Key, Vec<u8>>) -> Vec<UnknownInfo> {
	map.iter().map(|(k, v)| UnknownInfo {
		type_: k.type_value,
		key: k.key.clone().into(),
		value: v.clone().into(),
	}).collect()
}

/// A BIP-340 signature with its sighash type.
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct TaprootSignatureInfo {
	/// The full serialization as it appears in a witness: the signature
	/// followed by the sighash type byte unless it is SIGHASH_DEFAULT.
	pub hex: HexBytes,
	pub signature: HexBytes,
	pub sighash_type: String,
}

impl GetInfo<TaprootSignatureInfo> for taproot::Signature {
	fn get_info(&self, _network: Network) -> TaprootSignatureInfo {
		TaprootSignatureInfo {
			hex: self.to_vec().into(),
			signature: self.signature.as_ref()[..].into(),
			sighash_type: sighashtype_to_string(psbt::PsbtSighashType::from(self.sighash_type))
				.to_owned(),
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct TapScriptSigInfo {
	pub xonly_pubkey: XOnlyPublicKey,
	pub leaf_hash: TapLeafHash,
	pub signature: TaprootSignatureInfo,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct TapScriptInfo {
	pub control_block: tx::ControlBlockInfo,
	pub leaf_version: u8,
	pub leaf_hash: TapLeafHash,
	pub script: tx::InputScriptInfo,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct TapKeyOriginInfo {
	pub leaf_hashes: Vec<TapLeafHash>,
	pub master_fingerprint: bip32::Fingerprint,
	pub path: bip32::DerivationPath,
}

fn tap_key_origins_info(
	map: &std::collections::BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, bip32::KeySource)>,
) -> HashMap<XOnlyPublicKey, TapKeyOriginInfo> {
	map.iter().map(|(k, (leaf_hashes, source))| (*k, TapKeyOriginInfo {
		leaf_hashes: leaf_hashes.clone(),
		master_fingerprint: source.0,
		path: source.1.clone(),
	})).collect()
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct PsbtInputInfo {
	#[serde(skip_serializing_if = "Option::is_none")]
	pub non_witness_utxo: Option<tx::TransactionInfo>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub witness_utxo: Option<tx::OutputInfo>,
	#[serde(skip_serializing_if = "HashMap::is_empty")]
	pub partial_sigs: HashMap<HexBytes, HexBytes>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub sighash_type: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub redeem_script: Option<tx::OutputScriptInfo>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub witness_script: Option<tx::OutputScriptInfo>,
	#[serde(skip_serializing_if = "HashMap::is_empty")]
	pub bip32_derivation: HashMap<HexBytes, HDPathInfo>,
	#[deprecated(since = "0.9.5", note = "use bip32_derivation instead")]
	#[serde(skip_serializing_if = "HashMap::is_empty")]
	pub hd_keypaths: HashMap<HexBytes, HDPathInfo>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub final_script_sig: Option<tx::InputScriptInfo>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub final_script_witness: Option<Vec<HexBytes>>,
	#[serde(default, skip_serializing_if = "HashMap::is_empty")]
	pub ripemd160_preimages: HashMap<ripemd160::Hash, HexBytes>,
	#[serde(default, skip_serializing_if = "HashMap::is_empty")]
	pub sha256_preimages: HashMap<sha256::Hash, HexBytes>,
	#[serde(default, skip_serializing_if = "HashMap::is_empty")]
	pub hash160_preimages: HashMap<hash160::Hash, HexBytes>,
	#[serde(default, skip_serializing_if = "HashMap::is_empty")]
	pub hash256_preimages: HashMap<sha256d::Hash, HexBytes>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub tap_key_sig: Option<TaprootSignatureInfo>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub tap_script_sigs: Vec<TapScriptSigInfo>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub tap_scripts: Vec<TapScriptInfo>,
	#[serde(default, skip_serializing_if = "HashMap::is_empty")]
	pub tap_key_origins: HashMap<XOnlyPublicKey, TapKeyOriginInfo>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub tap_internal_key: Option<XOnlyPublicKey>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub tap_merkle_root: Option<TapNodeHash>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub proprietary: Vec<ProprietaryInfo>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub unknown: Vec<UnknownInfo>,
}

impl GetInfo<PsbtInputInfo> for psbt::Input {
	fn get_info(&self, network: Network) -> PsbtInputInfo {
		let bip32_derivation = {
			let mut ret = HashMap::new();
			for (key, value) in self.bip32_derivation.iter() {
				ret.insert(key.serialize().to_vec().into(), HDPathInfo::from(value));
			}
			ret
		};
		#[allow(deprecated)] // for hd_keypaths
		PsbtInputInfo {
			non_witness_utxo: self.non_witness_utxo.as_ref().map(|u| u.get_info(network)),
			witness_utxo: self.witness_utxo.as_ref().map(|u| u.get_info(network)),
			partial_sigs: {
				let mut partial_sigs = HashMap::new();
				for (key, value) in self.partial_sigs.iter() {
					partial_sigs.insert(key.to_bytes().into(), value.clone().to_vec().into());
				}
				partial_sigs
			},
			sighash_type: self.sighash_type.map(|s| sighashtype_to_string(s).to_owned()),
			redeem_script: self.redeem_script.as_ref()
				.map(|s| tx::OutputScript(s).get_info(network)),
			witness_script: self.witness_script.as_ref()
				.map(|s| tx::OutputScript(s).get_info(network)),
			bip32_derivation: bip32_derivation.clone(),
			hd_keypaths: bip32_derivation,
			final_script_sig: self.final_script_sig.as_ref()
				.map(|s| tx::InputScript(s).get_info(network)),
			final_script_witness: self.final_script_witness.as_ref()
				.map(|w| w.iter().map(|p| p.into()).collect()),
			ripemd160_preimages: self.ripemd160_preimages.iter()
				.map(|(k, v)| (*k, v.clone().into())).collect(),
			sha256_preimages: self.sha256_preimages.iter()
				.map(|(k, v)| (*k, v.clone().into())).collect(),
			hash160_preimages: self.hash160_preimages.iter()
				.map(|(k, v)| (*k, v.clone().into())).collect(),
			hash256_preimages: self.hash256_preimages.iter()
				.map(|(k, v)| (*k, v.clone().into())).collect(),
			tap_key_sig: self.tap_key_sig.as_ref().map(|s| s.get_info(network)),
			tap_script_sigs: self.tap_script_sigs.iter().map(|((pk, lh), sig)| TapScriptSigInfo {
				xonly_pubkey: *pk,
				leaf_hash: *lh,
				signature: sig.get_info(network),
			}).collect(),
			tap_scripts: self.tap_scripts.iter().map(|(cb, (script, version))| TapScriptInfo {
				control_block: cb.get_info(network),
				leaf_version: version.to_consensus(),
				leaf_hash: TapLeafHash::from_script(script, *version),
				script: tx::InputScript(script).get_info(network),
			}).collect(),
			tap_key_origins: tap_key_origins_info(&self.tap_key_origins),
			tap_internal_key: self.tap_internal_key,
			tap_merkle_root: self.tap_merkle_root,
			proprietary: proprietary_info(&self.proprietary),
			unknown: unknown_info(&self.unknown),
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct TapTreeLeafInfo {
	pub depth: u8,
	pub leaf_version: u8,
	pub leaf_hash: TapLeafHash,
	pub script: tx::InputScriptInfo,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct TapTreeInfo {
	pub root_hash: TapNodeHash,
	pub leaves: Vec<TapTreeLeafInfo>,
}

impl GetInfo<TapTreeInfo> for TapTree {
	fn get_info(&self, network: Network) -> TapTreeInfo {
		TapTreeInfo {
			root_hash: self.root_hash(),
			leaves: self.script_leaves().map(|leaf| TapTreeLeafInfo {
				depth: leaf.merkle_branch().len() as u8,
				leaf_version: leaf.version().to_consensus(),
				leaf_hash: TapLeafHash::from_script(leaf.script(), leaf.version()),
				script: tx::InputScript(leaf.script()).get_info(network),
			}).collect(),
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct PsbtOutputInfo {
	#[serde(skip_serializing_if = "Option::is_none")]
	pub redeem_script: Option<tx::OutputScriptInfo>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub witness_script: Option<tx::OutputScriptInfo>,
	#[serde(default, skip_serializing_if = "HashMap::is_empty")]
	pub bip32_derivation: HashMap<HexBytes, HDPathInfo>,
	#[deprecated(since = "0.12.0", note = "use bip32_derivation instead")]
	#[serde(skip_serializing_if = "HashMap::is_empty")]
	pub hd_keypaths: HashMap<HexBytes, HDPathInfo>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub tap_internal_key: Option<XOnlyPublicKey>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub tap_tree: Option<TapTreeInfo>,
	#[serde(default, skip_serializing_if = "HashMap::is_empty")]
	pub tap_key_origins: HashMap<XOnlyPublicKey, TapKeyOriginInfo>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub proprietary: Vec<ProprietaryInfo>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub unknown: Vec<UnknownInfo>,
}

impl GetInfo<PsbtOutputInfo> for psbt::Output {
	fn get_info(&self, network: Network) -> PsbtOutputInfo {
		let bip32_derivation = {
			let mut ret = HashMap::new();
			for (key, value) in self.bip32_derivation.iter() {
				ret.insert(key.serialize().to_vec().into(), HDPathInfo::from(value));
			}
			ret
		};
		#[allow(deprecated)] // for hd_keypaths
		PsbtOutputInfo {
			redeem_script: self.redeem_script.as_ref()
				.map(|s| tx::OutputScript(s).get_info(network)),
			witness_script: self.witness_script.as_ref()
				.map(|s| tx::OutputScript(s).get_info(network)),
			bip32_derivation: bip32_derivation.clone(),
			hd_keypaths: bip32_derivation,
			tap_internal_key: self.tap_internal_key,
			tap_tree: self.tap_tree.as_ref().map(|t| t.get_info(network)),
			tap_key_origins: tap_key_origins_info(&self.tap_key_origins),
			proprietary: proprietary_info(&self.proprietary),
			unknown: unknown_info(&self.unknown),
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct PsbtInfo {
	#[serde(default)]
	pub version: u32,
	pub unsigned_tx: tx::TransactionInfo,
	/// The fee paid by the transaction. Only present when the previous
	/// outputs of all inputs are known.
	#[serde(default, with = "bitcoin::amount::serde::as_sat::opt", skip_serializing_if = "Option::is_none")]
	pub fee: Option<Amount>,
	#[serde(default, skip_serializing_if = "HashMap::is_empty")]
	pub xpubs: HashMap<bip32::Xpub, HDPathInfo>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub proprietary: Vec<ProprietaryInfo>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub unknown: Vec<UnknownInfo>,
	pub inputs: Vec<PsbtInputInfo>,
	pub outputs: Vec<PsbtOutputInfo>,
}

impl GetInfo<PsbtInfo> for psbt::Psbt {
	fn get_info(&self, network: Network) -> PsbtInfo {
		PsbtInfo {
			version: self.version,
			unsigned_tx: self.unsigned_tx.get_info(network),
			fee: self.fee().ok(),
			xpubs: self.xpub.iter().map(|(k, v)| (*k, HDPathInfo::from(v))).collect(),
			proprietary: proprietary_info(&self.proprietary),
			unknown: unknown_info(&self.unknown),
			inputs: self.inputs.iter().map(|i| i.get_info(network)).collect(),
			outputs: self.outputs.iter().map(|o| o.get_info(network)).collect(),
		}
	}
}
