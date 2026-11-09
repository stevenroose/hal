use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use bitcoin::hashes::{hash160, ripemd160, sha256, sha256d};
use bitcoin::taproot::{self, TapLeafHash, TapNodeHash, TapTree};
use bitcoin::{
	absolute, bip32, psbt, secp256k1, sighash, Amount, Network, OutPoint, PublicKey, ScriptBuf,
	Sequence, Transaction, TxIn, TxOut, Txid, Witness, XOnlyPublicKey,
};
use std::collections::BTreeMap;
use psbt_v2::v2 as psbtv2;
pub use psbt_v2::v2::DetermineLockTimeError;

use crate::{tx, GetInfo, HexBytes};

/// BIP-370 PSBT_GLOBAL_TX_MODIFIABLE flag: inputs can be added or removed.
pub const TX_MODIFIABLE_INPUTS: u8 = 1 << 0;
/// BIP-370 PSBT_GLOBAL_TX_MODIFIABLE flag: outputs can be added or removed.
pub const TX_MODIFIABLE_OUTPUTS: u8 = 1 << 1;
/// BIP-370 PSBT_GLOBAL_TX_MODIFIABLE flag: a SIGHASH_SINGLE signature is present.
pub const TX_MODIFIABLE_SIGHASH_SINGLE: u8 = 1 << 2;

// The psbt-v2 crate has its own versions of some of the auxiliary types.

fn sighash_type_v0_to_v2(t: psbt::PsbtSighashType) -> psbt_v2::PsbtSighashType {
	psbt_v2::PsbtSighashType::from_u32(t.to_u32())
}

fn sighash_type_v2_to_v0(t: psbt_v2::PsbtSighashType) -> psbt::PsbtSighashType {
	psbt::PsbtSighashType::from_u32(t.to_u32())
}

fn bip32_v0_to_v2(
	map: BTreeMap<secp256k1::PublicKey, bip32::KeySource>,
) -> BTreeMap<PublicKey, bip32::KeySource> {
	map.into_iter().map(|(k, v)| (PublicKey::new(k), v)).collect()
}

fn bip32_v2_to_v0(
	map: BTreeMap<PublicKey, bip32::KeySource>,
) -> BTreeMap<secp256k1::PublicKey, bip32::KeySource> {
	map.into_iter().map(|(k, v)| (k.inner, v)).collect()
}

fn proprietary_v0_to_v2(
	map: BTreeMap<psbt::raw::ProprietaryKey, Vec<u8>>,
) -> BTreeMap<psbt_v2::raw::ProprietaryKey, Vec<u8>> {
	map.into_iter().map(|(k, v)| (psbt_v2::raw::ProprietaryKey {
		prefix: k.prefix,
		subtype: k.subtype,
		key: k.key,
	}, v)).collect()
}

fn proprietary_v2_to_v0(
	map: BTreeMap<psbt_v2::raw::ProprietaryKey, Vec<u8>>,
) -> BTreeMap<psbt::raw::ProprietaryKey, Vec<u8>> {
	map.into_iter().map(|(k, v)| (psbt::raw::ProprietaryKey {
		prefix: k.prefix,
		subtype: k.subtype,
		key: k.key,
	}, v)).collect()
}

fn unknown_v0_to_v2(
	map: BTreeMap<psbt::raw::Key, Vec<u8>>,
) -> BTreeMap<psbt_v2::raw::Key, Vec<u8>> {
	map.into_iter().map(|(k, v)| (psbt_v2::raw::Key {
		type_value: k.type_value,
		key: k.key,
	}, v)).collect()
}

fn unknown_v2_to_v0(
	map: BTreeMap<psbt_v2::raw::Key, Vec<u8>>,
) -> BTreeMap<psbt::raw::Key, Vec<u8>> {
	map.into_iter().map(|(k, v)| (psbt::raw::Key {
		type_value: k.type_value,
		key: k.key,
	}, v)).collect()
}

/// Convert a PSBTv0 input together with its transaction input to a PSBTv2 input.
pub fn input_v0_to_v2(txin: &TxIn, input: psbt::Input) -> psbtv2::Input {
	let mut ret = psbtv2::Input::new(&txin.previous_output);
	ret.sequence = if txin.sequence == Sequence::MAX {
		None
	} else {
		Some(txin.sequence)
	};
	ret.non_witness_utxo = input.non_witness_utxo;
	ret.witness_utxo = input.witness_utxo;
	ret.partial_sigs = input.partial_sigs;
	ret.sighash_type = input.sighash_type.map(sighash_type_v0_to_v2);
	ret.redeem_script = input.redeem_script;
	ret.witness_script = input.witness_script;
	ret.bip32_derivations = bip32_v0_to_v2(input.bip32_derivation);
	ret.final_script_sig = input.final_script_sig;
	ret.final_script_witness = input.final_script_witness;
	ret.ripemd160_preimages = input.ripemd160_preimages;
	ret.sha256_preimages = input.sha256_preimages;
	ret.hash160_preimages = input.hash160_preimages;
	ret.hash256_preimages = input.hash256_preimages;
	ret.tap_key_sig = input.tap_key_sig;
	ret.tap_script_sigs = input.tap_script_sigs;
	ret.tap_scripts = input.tap_scripts;
	ret.tap_key_origins = input.tap_key_origins;
	ret.tap_internal_key = input.tap_internal_key;
	ret.tap_merkle_root = input.tap_merkle_root;
	ret.proprietaries = proprietary_v0_to_v2(input.proprietary);
	ret.unknowns = unknown_v0_to_v2(input.unknown);
	ret
}

/// Convert a PSBTv2 input to a PSBTv0 input and its transaction input.
///
/// The required locktime fields are dropped as they are part of the
/// transaction's locktime in PSBTv0.
pub fn input_v2_to_v0(input: psbtv2::Input) -> (TxIn, psbt::Input) {
	let txin = TxIn {
		previous_output: OutPoint::new(input.previous_txid, input.spent_output_index),
		script_sig: ScriptBuf::new(),
		sequence: input.sequence.unwrap_or(Sequence::MAX),
		witness: Witness::new(),
	};
	let ret = psbt::Input {
		non_witness_utxo: input.non_witness_utxo,
		witness_utxo: input.witness_utxo,
		partial_sigs: input.partial_sigs,
		sighash_type: input.sighash_type.map(sighash_type_v2_to_v0),
		redeem_script: input.redeem_script,
		witness_script: input.witness_script,
		bip32_derivation: bip32_v2_to_v0(input.bip32_derivations),
		final_script_sig: input.final_script_sig,
		final_script_witness: input.final_script_witness,
		ripemd160_preimages: input.ripemd160_preimages,
		sha256_preimages: input.sha256_preimages,
		hash160_preimages: input.hash160_preimages,
		hash256_preimages: input.hash256_preimages,
		tap_key_sig: input.tap_key_sig,
		tap_script_sigs: input.tap_script_sigs,
		tap_scripts: input.tap_scripts,
		tap_key_origins: input.tap_key_origins,
		tap_internal_key: input.tap_internal_key,
		tap_merkle_root: input.tap_merkle_root,
		proprietary: proprietary_v2_to_v0(input.proprietaries),
		unknown: unknown_v2_to_v0(input.unknowns),
	};
	(txin, ret)
}

/// Convert a PSBTv0 output together with its transaction output to a PSBTv2 output.
pub fn output_v0_to_v2(txout: &TxOut, output: psbt::Output) -> psbtv2::Output {
	let mut ret = psbtv2::Output::new(txout.clone());
	ret.redeem_script = output.redeem_script;
	ret.witness_script = output.witness_script;
	ret.bip32_derivations = bip32_v0_to_v2(output.bip32_derivation);
	ret.tap_internal_key = output.tap_internal_key;
	ret.tap_tree = output.tap_tree;
	ret.tap_key_origins = output.tap_key_origins;
	ret.proprietaries = proprietary_v0_to_v2(output.proprietary);
	ret.unknowns = unknown_v0_to_v2(output.unknown);
	ret
}

/// Convert a PSBTv2 output to a PSBTv0 output and its transaction output.
pub fn output_v2_to_v0(output: psbtv2::Output) -> (TxOut, psbt::Output) {
	let txout = TxOut {
		value: output.amount,
		script_pubkey: output.script_pubkey,
	};
	let ret = psbt::Output {
		redeem_script: output.redeem_script,
		witness_script: output.witness_script,
		bip32_derivation: bip32_v2_to_v0(output.bip32_derivations),
		tap_internal_key: output.tap_internal_key,
		tap_tree: output.tap_tree,
		tap_key_origins: output.tap_key_origins,
		proprietary: proprietary_v2_to_v0(output.proprietaries),
		unknown: unknown_v2_to_v0(output.unknowns),
	};
	(txout, ret)
}

/// Convert a PSBTv0 to a PSBTv2.
///
/// Since the transaction of a PSBTv0 is fixed, the resulting PSBTv2 has no
/// modifiable flags set.
pub fn psbt_v0_to_v2(psbt: psbt::Psbt) -> psbtv2::Psbt {
	let tx = psbt.unsigned_tx;
	let mut global = psbtv2::Global::default();
	global.tx_version = tx.version;
	global.fallback_lock_time = if tx.lock_time == absolute::LockTime::ZERO {
		None
	} else {
		Some(tx.lock_time)
	};
	global.tx_modifiable_flags = 0;
	global.input_count = tx.input.len();
	global.output_count = tx.output.len();
	global.xpubs = psbt.xpub;
	global.proprietaries = proprietary_v0_to_v2(psbt.proprietary);
	global.unknowns = unknown_v0_to_v2(psbt.unknown);
	psbtv2::Psbt {
		global: global,
		inputs: tx.input.iter().zip(psbt.inputs.into_iter())
			.map(|(txin, input)| input_v0_to_v2(txin, input)).collect(),
		outputs: tx.output.iter().zip(psbt.outputs.into_iter())
			.map(|(txout, output)| output_v0_to_v2(txout, output)).collect(),
	}
}

/// Construct the unsigned transaction a PSBTv2 represents.
///
/// Fails when the inputs have conflicting locktime requirements.
pub fn psbt_v2_unsigned_tx(psbt: &psbtv2::Psbt) -> Result<Transaction, DetermineLockTimeError> {
	Ok(Transaction {
		version: psbt.global.tx_version,
		lock_time: psbt.determine_lock_time()?,
		input: psbt.inputs.iter().map(|i| input_v2_to_v0(i.clone()).0).collect(),
		output: psbt.outputs.iter().map(|o| output_v2_to_v0(o.clone()).0).collect(),
	})
}

/// Convert a PSBTv2 to a PSBTv0.
///
/// The modifiable flags and the per-input locktime requirements are lost,
/// the latter being folded into the transaction's locktime.
/// Fails when the inputs have conflicting locktime requirements.
pub fn psbt_v2_to_v0(psbt: psbtv2::Psbt) -> Result<psbt::Psbt, DetermineLockTimeError> {
	let lock_time = psbt.determine_lock_time()?;
	let (txins, inputs): (Vec<TxIn>, Vec<psbt::Input>) =
		psbt.inputs.into_iter().map(input_v2_to_v0).unzip();
	let (txouts, outputs): (Vec<TxOut>, Vec<psbt::Output>) =
		psbt.outputs.into_iter().map(output_v2_to_v0).unzip();
	Ok(psbt::Psbt {
		unsigned_tx: Transaction {
			version: psbt.global.tx_version,
			lock_time: lock_time,
			input: txins,
			output: txouts,
		},
		version: 0,
		xpub: psbt.global.xpubs,
		proprietary: proprietary_v2_to_v0(psbt.global.proprietaries),
		unknown: unknown_v2_to_v0(psbt.global.unknowns),
		inputs: inputs,
		outputs: outputs,
	})
}

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
	// PSBTv2 fields
	#[serde(skip_serializing_if = "Option::is_none")]
	pub previous_txid: Option<Txid>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub previous_vout: Option<u32>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub sequence: Option<u32>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub required_time_locktime: Option<u32>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub required_height_locktime: Option<u32>,

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
			previous_txid: None,
			previous_vout: None,
			sequence: None,
			required_time_locktime: None,
			required_height_locktime: None,
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

impl GetInfo<PsbtInputInfo> for psbtv2::Input {
	fn get_info(&self, network: Network) -> PsbtInputInfo {
		let (txin, input) = input_v2_to_v0(self.clone());
		PsbtInputInfo {
			previous_txid: Some(txin.previous_output.txid),
			previous_vout: Some(txin.previous_output.vout),
			sequence: self.sequence.map(|s| s.to_consensus_u32()),
			required_time_locktime: self.min_time.map(|t| t.to_consensus_u32()),
			required_height_locktime: self.min_height.map(|h| h.to_consensus_u32()),
			..input.get_info(network)
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
	// PSBTv2 fields
	#[serde(default, with = "bitcoin::amount::serde::as_sat::opt", skip_serializing_if = "Option::is_none")]
	pub amount: Option<Amount>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub script_pubkey: Option<tx::OutputScriptInfo>,

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
			amount: None,
			script_pubkey: None,
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

impl GetInfo<PsbtOutputInfo> for psbtv2::Output {
	fn get_info(&self, network: Network) -> PsbtOutputInfo {
		let (txout, output) = output_v2_to_v0(self.clone());
		PsbtOutputInfo {
			amount: Some(txout.value),
			script_pubkey: Some(tx::OutputScript(&txout.script_pubkey).get_info(network)),
			..output.get_info(network)
		}
	}
}

/// The PSBTv2 PSBT_GLOBAL_TX_MODIFIABLE flags.
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct TxModifiableInfo {
	pub inputs_modifiable: bool,
	pub outputs_modifiable: bool,
	pub has_sighash_single: bool,
}

impl TxModifiableInfo {
	pub fn from_flags(flags: u8) -> TxModifiableInfo {
		TxModifiableInfo {
			inputs_modifiable: flags & TX_MODIFIABLE_INPUTS != 0,
			outputs_modifiable: flags & TX_MODIFIABLE_OUTPUTS != 0,
			has_sighash_single: flags & TX_MODIFIABLE_SIGHASH_SINGLE != 0,
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct PsbtInfo {
	#[serde(default)]
	pub version: u32,
	/// The unsigned transaction. For PSBTv2 this is constructed from the
	/// PSBT fields and absent when the locktime requirements conflict.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub unsigned_tx: Option<tx::TransactionInfo>,
	// PSBTv2 fields
	#[serde(skip_serializing_if = "Option::is_none")]
	pub tx_version: Option<i32>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub fallback_locktime: Option<u32>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub input_count: Option<usize>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub output_count: Option<usize>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub tx_modifiable: Option<TxModifiableInfo>,
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
			unsigned_tx: Some(self.unsigned_tx.get_info(network)),
			tx_version: None,
			fallback_locktime: None,
			input_count: None,
			output_count: None,
			tx_modifiable: None,
			fee: self.fee().ok(),
			xpubs: self.xpub.iter().map(|(k, v)| (*k, HDPathInfo::from(v))).collect(),
			proprietary: proprietary_info(&self.proprietary),
			unknown: unknown_info(&self.unknown),
			inputs: self.inputs.iter().map(|i| i.get_info(network)).collect(),
			outputs: self.outputs.iter().map(|o| o.get_info(network)).collect(),
		}
	}
}

impl GetInfo<PsbtInfo> for psbtv2::Psbt {
	fn get_info(&self, network: Network) -> PsbtInfo {
		PsbtInfo {
			version: self.global.version.to_u32(),
			unsigned_tx: psbt_v2_unsigned_tx(self).ok().map(|tx| tx.get_info(network)),
			tx_version: Some(self.global.tx_version.0),
			fallback_locktime: self.global.fallback_lock_time.map(|l| l.to_consensus_u32()),
			input_count: Some(self.global.input_count),
			output_count: Some(self.global.output_count),
			tx_modifiable: Some(TxModifiableInfo::from_flags(self.global.tx_modifiable_flags)),
			fee: self.fee().ok(),
			xpubs: self.global.xpubs.iter().map(|(k, v)| (*k, HDPathInfo::from(v))).collect(),
			proprietary: proprietary_info(&proprietary_v2_to_v0(self.global.proprietaries.clone())),
			unknown: unknown_info(&unknown_v2_to_v0(self.global.unknowns.clone())),
			inputs: self.inputs.iter().map(|i| i.get_info(network)).collect(),
			outputs: self.outputs.iter().map(|o| o.get_info(network)).collect(),
		}
	}
}
