use bitcoin::{address, Address, Network, Script, ScriptHash, WScriptHash};
use serde::{Deserialize, Serialize};

use crate::{address::Addresses, tx, GetInfo, HexBytes};

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct ScriptInfo {
	pub hex: HexBytes,
	pub asm: String,
	pub size: usize,
	/// The type of output this script would be when used as a scriptPubkey.
	#[serde(rename = "type")]
	pub type_: String,
	/// The address of this script when used as a scriptPubkey.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub address: Option<Address<address::NetworkUnchecked>>,
	/// The dust limit in satoshi for an output with this scriptPubkey,
	/// using Bitcoin Core's default dust relay fee.
	pub dust_limit: u64,
	pub is_push_only: bool,
	/// The number of sigops counted accurately, i.e. CHECKMULTISIG counts
	/// as the number of keys when it is preceded by a push of the number.
	pub sigop_count: usize,
	/// The number of sigops using legacy counting, i.e. CHECKMULTISIG
	/// always counts as 20.
	pub sigop_count_legacy: usize,
	pub script_hash: ScriptHash,
	pub witness_script_hash: WScriptHash,
	/// The addresses when this script is used as a redeem or witness script.
	pub addresses: Addresses,
}

impl GetInfo<ScriptInfo> for Script {
	fn get_info(&self, network: Network) -> ScriptInfo {
		ScriptInfo {
			hex: self.to_bytes().into(),
			asm: self.to_asm_string(),
			size: self.len(),
			type_: tx::output_script_type(self).to_owned(),
			address: Address::from_script(self, network).ok().map(|a| a.as_unchecked().clone()),
			dust_limit: self.minimal_non_dust().to_sat(),
			is_push_only: self.is_push_only(),
			sigop_count: self.count_sigops(),
			sigop_count_legacy: self.count_sigops_legacy(),
			script_hash: self.script_hash(),
			witness_script_hash: self.wscript_hash(),
			addresses: Addresses::from_script(self, network),
		}
	}
}
