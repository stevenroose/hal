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

pub fn sighashtype_to_string(sht: psbt::PsbtSighashType) -> String {
	if let Ok(t) = sht.ecdsa_hash_ty() {
		match t {
			sighash::EcdsaSighashType::All => "ALL",
			sighash::EcdsaSighashType::None => "NONE",
			sighash::EcdsaSighashType::Single => "SINGLE",
			sighash::EcdsaSighashType::AllPlusAnyoneCanPay => "ALL|ANYONECANPAY",
			sighash::EcdsaSighashType::NonePlusAnyoneCanPay => "NONE|ANYONECANPAY",
			sighash::EcdsaSighashType::SinglePlusAnyoneCanPay => "SINGLE|ANYONECANPAY",
		}
	} else if let Ok(_) = sht.schnorr_hash_ty() {
		panic!("schnorr sigs are not yet supported");
	} else {
		unreachable!();
	}.to_owned()
}

pub fn sighashtype_values() -> &'static [&'static str] {
	&["ALL", "NONE", "SINGLE", "ALL|ANYONECANPAY", "NONE|ANYONECANPAY", "SINGLE|ANYONECANPAY"]
}

pub fn ecdsa_sighashtype_from_string(sht: &str) -> psbt::PsbtSighashType {
	use bitcoin::EcdsaSighashType::*;
	let ecdsa_sighash = match sht {
		"ALL" => All,
		"NONE" => None,
		"SINGLE" => Single,
		"ALL|ANYONECANPAY" => AllPlusAnyoneCanPay,
		"NONE|ANYONECANPAY" => NonePlusAnyoneCanPay,
		"SINGLE|ANYONECANPAY" => SinglePlusAnyoneCanPay,
		_ => panic!("invalid ecdsa SIGHASH type value -- possible values: {:?}", &sighashtype_values()),
	};
	psbt::PsbtSighashType::from(ecdsa_sighash)
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
	pub hd_keypaths: HashMap<HexBytes, HDPathInfo>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub final_script_sig: Option<tx::InputScriptInfo>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub final_script_witness: Option<Vec<HexBytes>>,
}

impl GetInfo<PsbtInputInfo> for psbt::Input {
	fn get_info(&self, network: Network) -> PsbtInputInfo {
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
			sighash_type: self.sighash_type.map(sighashtype_to_string),
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
			final_script_sig: self.final_script_sig.as_ref()
				.map(|s| tx::InputScript(s).get_info(network)),
			final_script_witness: self.final_script_witness.as_ref()
				.map(|w| w.iter().map(|p| p.clone().into()).collect()),
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
