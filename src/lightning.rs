
use bitcoin::{address, Address, Network};
use bitcoin::hashes::{sha256, Hash};
use chrono::{offset::Local, DateTime, Duration};
use lightning_invoice::{Bolt11Invoice, Currency, Bolt11InvoiceDescription, RouteHintHop};
use serde::{Deserialize, Serialize};

use crate::{GetInfo, HexBytes};

const WRONG_CID: &'static str = "incorrect short channel ID HRF format";

/// Parse a short channel is in the form of `${blockheight)x$(txindex}x${outputindex}`.
pub fn parse_short_channel_id(cid: &str) -> Result<u64, &'static str> {
	let mut split = cid.split("x");
	let blocknum: u64 = split.next().ok_or(WRONG_CID)?.parse().map_err(|_| WRONG_CID)?;
	if blocknum & 0xFFFFFF != blocknum {
		return Err(WRONG_CID);
	}
	let txnum: u64 = split.next().ok_or(WRONG_CID)?.parse().map_err(|_| WRONG_CID)?;
	if txnum & 0xFFFFFF != txnum {
		return Err(WRONG_CID);
	}
	let outnum: u64 = split.next().ok_or(WRONG_CID)?.parse().map_err(|_| WRONG_CID)?;
	if outnum & 0xFFFF != outnum {
		return Err(WRONG_CID);
	}
	Ok(blocknum << 40 | txnum << 16 | outnum)
}

/// Parse a short channel is in the form of `${blockheight)x$(txindex}x${outputindex}`.
pub fn fmt_short_channel_id(cid: u64) -> String {
	let blocknum = cid >> 40;
	let txnum = cid >> 16 & 0x00FFFFFF;
	let outnum = cid & 0xFFFF;
	format!("{}x{}x{}", blocknum, txnum, outnum)
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct RouteHopInfo {
	pub src_node_id: HexBytes,
	pub short_channel_id: u64,
	pub short_channel_id_hex: HexBytes,
	pub short_channel_id_hrf: String,
	pub fee_base_msat: u32,
	pub fee_proportional_millionths: u32,
	pub cltv_expiry_delta: u16,
}

impl GetInfo<RouteHopInfo> for RouteHintHop {
	fn get_info(&self, _network: Network) -> RouteHopInfo {
		RouteHopInfo {
			src_node_id: self.src_node_id.serialize()[..].into(),
			short_channel_id: self.short_channel_id,
			short_channel_id_hex: self.short_channel_id.to_be_bytes()[..].into(),
			short_channel_id_hrf: fmt_short_channel_id(self.short_channel_id),
			fee_base_msat: self.fees.base_msat,
			fee_proportional_millionths: self.fees.proportional_millionths,
			cltv_expiry_delta: self.cltv_expiry_delta,
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct InvoiceInfo {
	pub timestamp: DateTime<Local>,
	pub payment_hash: sha256::Hash,
	pub description: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub payee_pub_key: Option<HexBytes>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub expiry_time: Option<DateTime<Local>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub min_final_cltv_expiry: Option<u64>,
	#[serde(skip_serializing_if = "Vec::is_empty")]
	pub fallback_addresses: Vec<Address<address::NetworkUnchecked>>,
	#[serde(skip_serializing_if = "Vec::is_empty")]
	pub routes: Vec<Vec<RouteHopInfo>>,
	pub currency: String,

	// For signed invoices.
	pub signature: HexBytes,
	pub signature_recover_id: i32,
	pub payee_pubkey: Option<HexBytes>,
}

impl GetInfo<InvoiceInfo> for Bolt11Invoice {
	fn get_info(&self, network: Network) -> InvoiceInfo {
		let signed_raw = self.clone().into_signed_raw();
		let (sig_rec, sig) = signed_raw.signature().0.serialize_compact();

		InvoiceInfo {
			timestamp: self.timestamp().clone().into(),
			payment_hash: sha256::Hash::from_slice(&self.payment_hash()[..]).unwrap(),
			description: match self.description() {
				Bolt11InvoiceDescription::Direct(s) => s.clone().into_inner().0,
				Bolt11InvoiceDescription::Hash(h) => h.0.to_string(),
			},
			payee_pub_key: self.payee_pub_key().map(|pk| pk.serialize()[..].into()),
			expiry_time: Some(
				Local::now() + Duration::from_std(self.expiry_time())
					.expect("invalid expiry in invoice"),
			),
			min_final_cltv_expiry: Some(self.min_final_cltv_expiry_delta()),
			fallback_addresses: self.fallback_addresses().into_iter()
				.map(|a| a.to_string().parse().unwrap()).collect(),
			routes: self.route_hints()
				.iter().map(|r| r.0.iter().map(|h| GetInfo::get_info(h, network)).collect())
				.collect(),
			currency: match self.currency() {
				Currency::Bitcoin => "bitcoin".to_owned(),
				Currency::BitcoinTestnet => "bitcoin-testnet".to_owned(),
				Currency::Regtest => "bitcoin-regtest".to_owned(),
				Currency::Simnet => "bitcoin-simnet".to_owned(),
				Currency::Signet => "bitcoin-signet".to_owned(),
			},
			signature: sig[..].into(),
			signature_recover_id: sig_rec.to_i32(),
			payee_pubkey: signed_raw
				.recover_payee_pub_key()
				.ok()
				.map(|s| s.0.serialize()[..].into()),
		}
	}
}
