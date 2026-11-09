use bitcoin::pow::{CompactTarget, Target};
use bitcoin::Network;
use serde::{Deserialize, Serialize};

use crate::GetInfo;

/// Information about a proof-of-work target.
#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct TargetInfo {
	/// The compact encoding of the target as used in block headers.
	pub bits: u32,
	/// The compact encoding of the target in hex.
	pub bits_hex: String,
	/// The target as a 256-bit hex number.
	pub target: String,
	/// The difficulty relative to the selected network's maximum target.
	pub difficulty: u128,
	/// The expected amount of work to find a block with this target, as a 256-bit hex number.
	pub work: String,
}

impl GetInfo<TargetInfo> for Target {
	fn get_info(&self, network: Network) -> TargetInfo {
		let bits = self.to_compact_lossy();
		TargetInfo {
			bits: bits.to_consensus(),
			bits_hex: format!("{:08x}", bits.to_consensus()),
			target: format!("{:064x}", self),
			difficulty: self.difficulty(network),
			work: format!("{:064x}", self.to_work()),
		}
	}
}

impl GetInfo<TargetInfo> for CompactTarget {
	fn get_info(&self, network: Network) -> TargetInfo {
		TargetInfo {
			bits: self.to_consensus(),
			bits_hex: format!("{:08x}", self.to_consensus()),
			..Target::from_compact(*self).get_info(network)
		}
	}
}
