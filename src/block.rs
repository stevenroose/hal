use bitcoin::{block, Block, BlockHash, Network, TxMerkleNode, Txid};
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
	pub nonce: u32,
}

impl<'a> GetInfo<BlockHeaderInfo> for block::Header {
	fn get_info(&self, _network: Network) -> BlockHeaderInfo {
		BlockHeaderInfo {
			block_hash: Some(self.block_hash()),
			version: self.version.to_consensus(),
			previous_block_hash: self.prev_blockhash,
			merkle_root: self.merkle_root,
			time: self.time,
			bits: self.bits.to_consensus(),
			nonce: self.nonce,
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct BlockInfo {
	pub header: BlockHeaderInfo,
	pub bip34_block_height: Option<u64>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub transactions: Option<Vec<TransactionInfo>>,

	#[serde(skip_serializing_if = "Option::is_none")]
	pub txids: Option<Vec<Txid>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub raw_transactions: Option<Vec<HexBytes>>,
}

impl GetInfo<BlockInfo> for Block {
	fn get_info(&self, network: Network) -> BlockInfo {
		BlockInfo {
			header: self.header.get_info(network),
			bip34_block_height: self.bip34_block_height().ok(),
			transactions: Some(self.txdata.iter().map(|t| t.get_info(network)).collect()),
			txids: None,
			raw_transactions: None,
		}
	}
}
