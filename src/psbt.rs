use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use bitcoin::util::{bip32, sighash, psbt};
use bitcoin::Network;

use crate::{tx, GetInfo, HexBytes};

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct HDPathInfo {
	pub master_fingerprint: bip32::Fingerprint,
	pub path: bip32::DerivationPath,
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
	} else if let Ok(t) = sht.schnorr_hash_ty() {
		match t {
            sighash::SchnorrSighashType::Default => "SIGHASH_DEFAULT",
            sighash::SchnorrSighashType::All => "SIGHASH_ALL",
            sighash::SchnorrSighashType::None => "SIGHASH_NONE",
            sighash::SchnorrSighashType::Single => "SIGHASH_SINGLE",
            sighash::SchnorrSighashType::AllPlusAnyoneCanPay => "SIGHASH_ALL|SIGHASH_ANYONECANPAY",
            sighash::SchnorrSighashType::NonePlusAnyoneCanPay => "SIGHASH_NONE|SIGHASH_ANYONECANPAY",
            sighash::SchnorrSighashType::SinglePlusAnyoneCanPay => "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY",
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
}

impl GetInfo<PsbtInputInfo> for psbt::Input {
	fn get_info(&self, network: Network) -> PsbtInputInfo {
		let bip32_derivation = {
			let mut ret = HashMap::new();
			for (key, value) in self.bip32_derivation.iter() {
				ret.insert(key.serialize().to_vec().into(),
					HDPathInfo {
						master_fingerprint: value.0[..].into(),
						path: value.1.clone(),
					},
				);
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
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct PsbtOutputInfo {
	#[serde(skip_serializing_if = "Option::is_none")]
	pub redeem_script: Option<tx::OutputScriptInfo>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub witness_script: Option<tx::OutputScriptInfo>,
	#[serde(skip_serializing_if = "HashMap::is_empty")]
	pub hd_keypaths: HashMap<HexBytes, HDPathInfo>,
}

impl GetInfo<PsbtOutputInfo> for psbt::Output {
	fn get_info(&self, network: Network) -> PsbtOutputInfo {
		PsbtOutputInfo {
			redeem_script: self.redeem_script.as_ref()
				.map(|s| tx::OutputScript(s).get_info(network)),
			witness_script: self.witness_script.as_ref()
				.map(|s| tx::OutputScript(s).get_info(network)),
			hd_keypaths: {
				let mut hd_keypaths = HashMap::new();
				for (key, value) in self.bip32_derivation.iter() {
					hd_keypaths.insert(key.serialize().to_vec().into(),
						HDPathInfo {
							master_fingerprint: value.0[..].into(),
							path: value.1.clone(),
						},
					);
				}
				hd_keypaths
			},
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct PsbtInfo {
	pub unsigned_tx: tx::TransactionInfo,
	pub inputs: Vec<PsbtInputInfo>,
	pub outputs: Vec<PsbtOutputInfo>,
}

impl GetInfo<PsbtInfo> for psbt::PartiallySignedTransaction {
	fn get_info(&self, network: Network) -> PsbtInfo {
		PsbtInfo {
			unsigned_tx: self.unsigned_tx.get_info(network),
			inputs: self.inputs.iter().map(|i| i.get_info(network)).collect(),
			outputs: self.outputs.iter().map(|o| o.get_info(network)).collect(),
		}
	}
}
