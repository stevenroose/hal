use bitcoin::consensus::encode::serialize;
use bitcoin::taproot::{ControlBlock, TapNodeHash};
use bitcoin::{
	address, relative, Address, Amount, Network, Script, Transaction, TxIn, TxOut, Txid, Witness,
	Wtxid, XOnlyPublicKey,
};
use serde::{Deserialize, Serialize};

use crate::{GetInfo, HexBytes};

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct InputScriptInfo {
	pub hex: Option<HexBytes>,
	pub asm: Option<String>,
}

pub struct InputScript<'a>(pub &'a Script);

impl<'a> GetInfo<InputScriptInfo> for InputScript<'a> {
	fn get_info(&self, _network: Network) -> InputScriptInfo {
		InputScriptInfo {
			hex: Some(self.0.to_bytes().into()),
			asm: Some(self.0.to_asm_string()),
		}
	}
}

/// A relative locktime as encoded in an input's sequence number (BIP-68).
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum RelativeLockTimeInfo {
	#[serde(rename = "height")]
	Height {
		blocks: u16,
	},
	#[serde(rename = "time")]
	Time {
		/// Number of 512-second intervals.
		intervals: u16,
		seconds: u32,
	},
}

impl GetInfo<RelativeLockTimeInfo> for relative::LockTime {
	fn get_info(&self, _network: Network) -> RelativeLockTimeInfo {
		match self {
			relative::LockTime::Blocks(h) => RelativeLockTimeInfo::Height {
				blocks: h.value(),
			},
			relative::LockTime::Time(t) => RelativeLockTimeInfo::Time {
				intervals: t.value(),
				seconds: t.value() as u32 * 512,
			},
		}
	}
}

/// The decoded taproot control block of a script-path spend.
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct ControlBlockInfo {
	pub hex: HexBytes,
	pub leaf_version: u8,
	/// Parity of the output key: 0 for even, 1 for odd.
	pub output_key_parity: u8,
	pub internal_key: XOnlyPublicKey,
	pub merkle_branch: Vec<TapNodeHash>,
}

impl GetInfo<ControlBlockInfo> for ControlBlock {
	fn get_info(&self, _network: Network) -> ControlBlockInfo {
		ControlBlockInfo {
			hex: self.serialize().into(),
			leaf_version: self.leaf_version.to_consensus(),
			output_key_parity: self.output_key_parity.to_u8(),
			internal_key: self.internal_key,
			merkle_branch: self.merkle_branch.as_slice().to_vec(),
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct InputInfo {
	pub prevout: Option<String>,
	pub txid: Option<Txid>,
	pub vout: Option<u32>,
	pub script_sig: Option<InputScriptInfo>,
	pub sequence: Option<u32>,
	/// Whether the sequence number signals opt-in replace-by-fee (BIP-125).
	#[serde(skip_serializing_if = "Option::is_none")]
	pub is_rbf: Option<bool>,
	/// The relative locktime encoded in the sequence number, if enabled.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub relative_locktime: Option<RelativeLockTimeInfo>,
	pub witness: Option<Vec<HexBytes>>,
	/// Best-effort interpretation of the witness as a taproot script-path spend.
	/// Only set when the witness has a validly encoded control block.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub tapscript: Option<InputScriptInfo>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub taproot_control_block: Option<ControlBlockInfo>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub taproot_annex: Option<HexBytes>,
}

/// Try to interpret the witness as a taproot script-path spend.
///
/// This is a heuristic because we don't have the spent output here, so we
/// only report when the control block parses validly.
fn taproot_witness_info(
	witness: &Witness,
	network: Network,
) -> (Option<InputScriptInfo>, Option<ControlBlockInfo>, Option<HexBytes>) {
	let control_block = match witness.taproot_control_block().and_then(|b| ControlBlock::decode(b).ok()) {
		Some(cb) => cb,
		None => return (None, None, None),
	};
	(
		witness.taproot_leaf_script().map(|s| InputScript(s.script).get_info(network)),
		Some(control_block.get_info(network)),
		witness.taproot_annex().map(|a| a.into()),
	)
}

impl GetInfo<InputInfo> for TxIn {
	fn get_info(&self, network: Network) -> InputInfo {
		let (tapscript, taproot_control_block, taproot_annex) =
			taproot_witness_info(&self.witness, network);
		InputInfo {
			prevout: Some(self.previous_output.to_string()),
			txid: Some(self.previous_output.txid),
			vout: Some(self.previous_output.vout),
			sequence: Some(self.sequence.to_consensus_u32()),
			is_rbf: Some(self.sequence.is_rbf()),
			relative_locktime: self.sequence.to_relative_lock_time()
				.map(|lt| lt.get_info(network)),
			script_sig: Some(InputScript(&self.script_sig).get_info(network)),
			witness: if self.witness.len() > 0 {
				Some(self.witness.iter().map(|h| h.into()).collect())
			} else {
				None
			},
			tapscript: tapscript,
			taproot_control_block: taproot_control_block,
			taproot_annex: taproot_annex,
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct OutputScriptInfo {
	pub hex: Option<HexBytes>,
	pub asm: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none", rename = "type")]
	pub type_: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub address: Option<Address<address::NetworkUnchecked>>,
}

/// Name the type of the given scriptPubkey.
pub fn output_script_type(script: &Script) -> &'static str {
	if script.is_p2pk() {
		"p2pk"
	} else if script.is_p2pkh() {
		"p2pkh"
	} else if script.is_op_return() {
		"opreturn"
	} else if script.is_p2sh() {
		"p2sh"
	} else if script.is_p2wpkh() {
		"p2wpkh"
	} else if script.is_p2wsh() {
		"p2wsh"
	} else if script.is_p2tr() {
		"p2tr"
	} else if script.as_bytes() == [0x51, 0x02, 0x4e, 0x73] {
		// OP_1 <0x4e73>: pay-to-anchor
		"p2a"
	} else if script.is_witness_program() {
		"unknown-witness-program-version"
	} else if script.is_multisig() {
		"multisig"
	} else {
		"unknown"
	}
}

pub struct OutputScript<'a>(pub &'a Script);

impl<'a> GetInfo<OutputScriptInfo> for OutputScript<'a> {
	fn get_info(&self, network: Network) -> OutputScriptInfo {
		OutputScriptInfo {
			hex: Some(self.0.to_bytes().into()),
			asm: Some(self.0.to_asm_string()),
			type_: Some(output_script_type(self.0).to_owned()),
			address: Address::from_script(&self.0, network).ok().map(|a| a.as_unchecked().clone()),
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct OutputInfo {
	#[serde(with = "bitcoin::amount::serde::as_sat::opt")]
	pub value: Option<Amount>,
	pub script_pub_key: Option<OutputScriptInfo>,
}

impl GetInfo<OutputInfo> for TxOut {
	fn get_info(&self, network: Network) -> OutputInfo {
		OutputInfo {
			value: Some(self.value),
			script_pub_key: Some(OutputScript(&self.script_pubkey).get_info(network)),
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct TransactionInfo {
	pub txid: Option<Txid>,
	pub wtxid: Option<Wtxid>,
	pub size: Option<usize>,
	/// The size of the transaction without witness data.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub base_size: Option<usize>,
	pub weight: Option<usize>,
	pub vsize: Option<usize>,
	pub version: Option<i32>,
	pub locktime: Option<u32>,
	/// Whether the locktime is interpreted as a block height or a unix time.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub locktime_type: Option<String>,
	/// Whether the locktime is enforced, i.e. at least one input has a
	/// non-final sequence number.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub locktime_enabled: Option<bool>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub is_coinbase: Option<bool>,
	/// Whether at least one input signals opt-in replace-by-fee (BIP-125).
	#[serde(skip_serializing_if = "Option::is_none")]
	pub is_explicitly_rbf: Option<bool>,
	pub inputs: Option<Vec<InputInfo>>,
	pub outputs: Option<Vec<OutputInfo>>,
	pub total_output_value: Option<u64>,
}

impl GetInfo<TransactionInfo> for Transaction {
	fn get_info(&self, network: Network) -> TransactionInfo {
		TransactionInfo {
			txid: Some(self.compute_txid()),
			wtxid: Some(self.compute_wtxid()),
			version: Some(self.version.0),
			locktime: Some(self.lock_time.to_consensus_u32()),
			locktime_type: Some(if self.lock_time.is_block_height() {
				"height".to_owned()
			} else {
				"time".to_owned()
			}),
			locktime_enabled: Some(self.is_lock_time_enabled()),
			is_coinbase: Some(self.is_coinbase()),
			is_explicitly_rbf: Some(self.is_explicitly_rbf()),
			size: Some(serialize(self).len()),
			base_size: Some(self.base_size()),
			weight: Some(self.weight().to_wu() as usize),
			vsize: Some(self.vsize()),
			inputs: Some(self.input.iter().map(|i| i.get_info(network)).collect()),
			outputs: Some(self.output.iter().map(|o| o.get_info(network)).collect()),
			total_output_value: Some(self.output.iter().map(|o| o.value.to_sat()).sum()),
		}
	}
}
