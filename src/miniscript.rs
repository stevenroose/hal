use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyKeyType {
	PublicKey,
	String,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct PolicyInfo {
	pub is_concrete: bool,
	pub key_type: PolicyKeyType,
	pub is_trivial: bool,
	pub is_unsatisfiable: bool,
	pub relative_timelocks: Vec<u32>,
	pub n_keys: usize,
	pub minimum_n_keys: usize,
	pub sorted: String,
	pub normalized: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub miniscript: Option<String>,
}
