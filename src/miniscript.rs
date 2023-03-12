use serde::{Deserialize, Serialize};

use crate::HexBytes;

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MiniscriptKeyType {
	PublicKey,
	String,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct ScriptContexts {
	pub bare: bool, // in bare script pubkey
	pub p2sh: bool,
	pub segwitv0: bool,
}

impl ScriptContexts {

	pub fn from_bare(bare: bool) -> Self {
		Self {
			bare: bare,
			p2sh: false,
			segwitv0: false,
		}
	}

	pub fn from_p2sh(p2sh: bool) -> Self {
		Self {
			bare: false,
			p2sh: p2sh,
			segwitv0: false,
		}
	}

	pub fn from_segwitv0(segwitv0: bool) -> Self {
		Self {
			bare: false,
			p2sh: false,
			segwitv0: segwitv0,
		}
	}

	pub fn or(a: Self, b: Self) -> Self {
		Self {
			bare: a.bare || b.bare,
			p2sh: a.p2sh || b.p2sh,
			segwitv0: a.segwitv0 || b.segwitv0,
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize)]
pub struct Miniscripts {
	#[serde(skip_serializing_if = "Option::is_none")]
	pub bare: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub p2sh: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub segwitv0: Option<String>,
	// Taproot to come
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct DescriptorInfo {
	pub descriptor: String,
	pub key_type: MiniscriptKeyType,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub address: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub script_pubkey: Option<HexBytes>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub unsigned_script_sig: Option<HexBytes>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub witness_script: Option<HexBytes>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub max_satisfaction_weight: Option<usize>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub policy: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct MiniscriptInfo {
	pub key_type: MiniscriptKeyType,
	pub valid_script_contexts: ScriptContexts,
	pub requires_sig: bool,
	pub has_mixed_timelocks: bool,
	pub has_repeated_keys: bool,
	pub non_malleable: ScriptContexts,
	pub within_resource_limits: ScriptContexts,
	pub sane_miniscript: ScriptContexts,
	pub script_size: usize,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub max_satisfaction_witness_elements: Option<usize>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub max_satisfaction_size_segwit: Option<usize>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub max_satisfaction_size_non_segwit: Option<usize>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub script: Option<HexBytes>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub policy: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct PolicyInfo {
	pub is_concrete: bool,
	pub key_type: MiniscriptKeyType,
	pub is_trivial: bool,
	pub is_unsatisfiable: bool,
	pub relative_timelocks: Vec<u32>,
	pub n_keys: usize,
	pub minimum_n_keys: usize,
	pub sorted: String,
	pub normalized: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub miniscript: Option<Miniscripts>,
}
