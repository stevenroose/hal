use bitcoin::hashes::sha256d;
use bitcoin::util::hash::BitcoinHash;
use bitcoin::{Block, BlockHeader, Network};
use serde::{Deserialize, Serialize};

use tx::TransactionInfo;

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct BlockHeaderInfo {
	#[serde(skip_serializing_if = "Option::is_none")]
	pub block_hash: Option<sha256d::Hash>,
	pub version: u32,
	pub previous_block_hash: sha256d::Hash,
	pub merkle_root: sha256d::Hash,
	pub time: u32,
	pub bits: u32,
	pub nonce: u32,
}

impl<'a> ::GetInfo<BlockHeaderInfo> for BlockHeader {
	fn get_info(&self, _network: Network) -> BlockHeaderInfo {
		BlockHeaderInfo {
			block_hash: Some(self.bitcoin_hash()),
			version: self.version,
			previous_block_hash: self.prev_blockhash,
			merkle_root: self.merkle_root,
			time: self.time,
			bits: self.bits,
			nonce: self.nonce,
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct BlockInfo {
	pub header: BlockHeaderInfo,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub transactions: Option<Vec<TransactionInfo>>,

	#[serde(skip_serializing_if = "Option::is_none")]
	pub txids: Option<Vec<sha256d::Hash>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub raw_transactions: Option<Vec<::HexBytes>>,
}

impl ::GetInfo<BlockInfo> for Block {
	fn get_info(&self, network: Network) -> BlockInfo {
		BlockInfo {
			header: self.header.get_info(network),
			transactions: Some(self.txdata.iter().map(|t| t.get_info(network)).collect()),
			txids: None,
			raw_transactions: None,
		}
	}
}
