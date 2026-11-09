use bitcoin::{block, Block, BlockHash, Network, TxMerkleNode, Txid, WitnessMerkleNode};
use serde::{Deserialize, Serialize};

use crate::tx::TransactionInfo;
use crate::{GetInfo, HexBytes};

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct BlockHeaderInfo {
	#[serde(skip_serializing_if = "Option::is_none")]
	pub block_hash: Option<BlockHash>,
	pub version: i32,
	pub previous_block_hash: BlockHash,
	pub merkle_root: TxMerkleNode,
	pub time: u32,
	pub bits: u32,
	/// The target threshold encoded by the bits field, as a 256-bit hex number.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub target: Option<String>,
	/// The difficulty relative to the network's maximum target.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub difficulty: Option<u128>,
	/// The expected amount of work needed to find this block, as a 256-bit hex number.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub work: Option<String>,
	pub nonce: u32,
}

impl<'a> GetInfo<BlockHeaderInfo> for block::Header {
	fn get_info(&self, network: Network) -> BlockHeaderInfo {
		BlockHeaderInfo {
			block_hash: Some(self.block_hash()),
			version: self.version.to_consensus(),
			previous_block_hash: self.prev_blockhash,
			merkle_root: self.merkle_root,
			time: self.time,
			bits: self.bits.to_consensus(),
			target: Some(format!("{:064x}", self.target())),
			difficulty: Some(self.difficulty(network)),
			work: Some(format!("{:064x}", self.work())),
			nonce: self.nonce,
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct BlockInfo {
	pub header: BlockHeaderInfo,
	pub bip34_block_height: Option<u64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub size: Option<usize>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub weight: Option<usize>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub nb_transactions: Option<usize>,
	/// Whether the merkle root in the header matches the transactions.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub merkle_root_valid: Option<bool>,
	/// The merkle root of the wtxids of the transactions.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub witness_root: Option<WitnessMerkleNode>,
	/// Whether the witness commitment in the coinbase matches the
	/// transactions. Also true when there is no witness data in the block.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub witness_commitment_valid: Option<bool>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub transactions: Option<Vec<TransactionInfo>>,

	#[serde(skip_serializing_if = "Option::is_none")]
	pub txids: Option<Vec<Txid>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub raw_transactions: Option<Vec<HexBytes>>,
}

impl BlockInfo {
	/// Create the info of the block without any transaction info filled in.
	///
	/// This fills in the header and the fields derived from the transaction
	/// list, but leaves `transactions`, `txids` and `raw_transactions` empty.
	/// When the block has no transactions (as is the case when only a header
	/// was parsed), the transaction-derived fields are left empty.
	pub fn without_transactions(block: &Block, network: Network) -> BlockInfo {
		let has_txs = !block.txdata.is_empty();
		BlockInfo {
			header: block.header.get_info(network),
			bip34_block_height: block.bip34_block_height().ok(),
			size: if has_txs { Some(block.total_size()) } else { None },
			weight: if has_txs { Some(block.weight().to_wu() as usize) } else { None },
			nb_transactions: if has_txs { Some(block.txdata.len()) } else { None },
			merkle_root_valid: if has_txs { Some(block.check_merkle_root()) } else { None },
			witness_root: if has_txs { block.witness_root() } else { None },
			witness_commitment_valid: if has_txs {
				Some(block.check_witness_commitment())
			} else {
				None
			},
			transactions: None,
			txids: None,
			raw_transactions: None,
		}
	}
}

impl GetInfo<BlockInfo> for Block {
	fn get_info(&self, network: Network) -> BlockInfo {
		BlockInfo {
			transactions: Some(self.txdata.iter().map(|t| t.get_info(network)).collect()),
			..BlockInfo::without_transactions(self, network)
		}
	}
}
