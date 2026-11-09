
use ark::address::{ArkId, Address, VtxoDelivery};
use ark::lightning::PaymentHash;
use ark::mailbox::BlindedMailboxIdentifier;
use ark::VtxoPolicy;
use bitcoin::Network;
use bitcoin::secp256k1::{PublicKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};

use crate::{GetInfo, HexBytes};

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum BarkVtxoPolicyInfo {
	#[serde(rename = "pubkey")]
	Pubkey {
		user_pubkey: PublicKey,
	},
	#[serde(rename = "server-htlc-send")]
	ServerHtlcSend {
		user_pubkey: PublicKey,
		payment_hash: PaymentHash,
		htlc_expiry: u32,
	},
	/// The legacy version of the server HTLC send policy.
	#[serde(rename = "server-htlc-send-v0")]
	ServerHtlcSendV0 {
		user_pubkey: PublicKey,
		payment_hash: PaymentHash,
		htlc_expiry: u32,
	},
	#[serde(rename = "server-htlc-receive")]
	ServerHtlcRecv {
		user_pubkey: PublicKey,
		payment_hash: PaymentHash,
		htlc_expiry_delta: u16,
		htlc_expiry: u32,
	},
	/// The legacy version of the server HTLC receive policy.
	#[serde(rename = "server-htlc-receive-v0")]
	ServerHtlcRecvV0 {
		user_pubkey: PublicKey,
		payment_hash: PaymentHash,
		htlc_expiry_delta: u16,
		htlc_expiry: u32,
	},
}

impl GetInfo<BarkVtxoPolicyInfo> for VtxoPolicy {
	fn get_info(&self, _: Network) -> BarkVtxoPolicyInfo {
		match self {
			VtxoPolicy::Pubkey(p) => BarkVtxoPolicyInfo::Pubkey {
				user_pubkey: p.user_pubkey,
			},
			VtxoPolicy::ServerHtlcSend(p) => BarkVtxoPolicyInfo::ServerHtlcSend {
				user_pubkey: p.user_pubkey,
				payment_hash: p.payment_hash,
				htlc_expiry: p.htlc_expiry.to_u32(),
			},
			VtxoPolicy::ServerHtlcSend_v0(p) => BarkVtxoPolicyInfo::ServerHtlcSendV0 {
				user_pubkey: p.user_pubkey,
				payment_hash: p.payment_hash,
				htlc_expiry: p.htlc_expiry.to_u32(),
			},
			VtxoPolicy::ServerHtlcRecv(p) => BarkVtxoPolicyInfo::ServerHtlcRecv {
				user_pubkey: p.user_pubkey,
				payment_hash: p.payment_hash,
				htlc_expiry_delta: p.htlc_expiry_delta.to_u16(),
				htlc_expiry: p.htlc_expiry.to_u32(),
			},
			VtxoPolicy::ServerHtlcRecv_v0(p) => BarkVtxoPolicyInfo::ServerHtlcRecvV0 {
				user_pubkey: p.user_pubkey,
				payment_hash: p.payment_hash,
				htlc_expiry_delta: p.htlc_expiry_delta.to_u16(),
				htlc_expiry: p.htlc_expiry.to_u32(),
			},
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum BarkVtxoDeliveryInfo {
	#[serde(rename = "server-builtin")]
	ServerBuiltin,
	#[serde(rename = "server-mailbox")]
	ServerMailbox {
		blinded_mailbox_id: BlindedMailboxIdentifier,
	},
	#[serde(rename = "unknown")]
	Unknown {
		delivery_type_byte: u8,
		data: HexBytes,
	},
}

impl GetInfo<BarkVtxoDeliveryInfo> for VtxoDelivery {
	fn get_info(&self, _network: Network) -> BarkVtxoDeliveryInfo {
		match self {
			VtxoDelivery::ServerMailbox { blinded_id } => BarkVtxoDeliveryInfo::ServerMailbox {
				blinded_mailbox_id: *blinded_id,
			},
			VtxoDelivery::Unknown { delivery_type, data } => BarkVtxoDeliveryInfo::Unknown {
				delivery_type_byte: *delivery_type,
				data: data.clone().into(),
			},
			// this means upstream lib added a type and we forgot to update
			_ => BarkVtxoDeliveryInfo::Unknown {
				delivery_type_byte: u8::MAX,
				data: HexBytes(vec![]),
			},
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct BarkAddressInfo {
	pub testnet: bool,
	pub ark_id: ArkId,
	pub policy: BarkVtxoPolicyInfo,
	pub delivery: Vec<BarkVtxoDeliveryInfo>,
}

impl GetInfo<BarkAddressInfo> for Address {
	fn get_info(&self, network: Network) -> BarkAddressInfo {
		BarkAddressInfo {
			testnet: self.is_testnet(),
			ark_id: self.ark_id(),
			policy: self.policy().get_info(network),
			delivery: self.delivery().iter().map(|d| d.clone().get_info(network)).collect(),
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct ArkadeAddressInfo {
	pub testnet: bool,
	pub user_pubkey: XOnlyPublicKey,
	pub server_pubkey: XOnlyPublicKey,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum ArkAddressInfo {
	#[serde(rename = "bark")]
	Bark(BarkAddressInfo),
	#[serde(rename = "arkade")]
	Arkade(ArkadeAddressInfo),
}
