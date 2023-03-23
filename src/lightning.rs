use std::convert::TryFrom;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::util::address::{Payload, WitnessVersion};
use bitcoin::{Address, Network};
use byteorder::{BigEndian, ByteOrder};
use chrono::{offset::Local, DateTime, Duration};
use lightning_invoice::{Currency, Fallback, Invoice, InvoiceDescription, RouteHop};
use serde::{Deserialize, Serialize};

use crate::{GetInfo, HexBytes};

const WRONG_CID: &'static str = "incorrect short channel ID HRF format";

/// Parse a short channel is in the form of `${blockheight)x$(txindex}x${outputindex}`.
pub fn parse_short_channel_id(cid: &str) -> u64 {
	let mut split = cid.split("x");
	let blocknum: u64 = split.next().expect(WRONG_CID).parse().expect(WRONG_CID);
	if blocknum & 0xFFFFFF != blocknum {
		panic!("{}", WRONG_CID);
	}
	let txnum: u64 = split.next().expect(WRONG_CID).parse().expect(WRONG_CID);
	if txnum & 0xFFFFFF != txnum {
		panic!("{}", WRONG_CID);
	}
	let outnum: u64 = split.next().expect(WRONG_CID).parse().expect(WRONG_CID);
	if outnum & 0xFFFF != outnum {
		panic!("{}", WRONG_CID);
	}
	blocknum << 40 | txnum << 16 | outnum
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
	pub pubkey: HexBytes,
	pub short_channel_id: u64,
	pub short_channel_id_hex: HexBytes,
	pub short_channel_id_hrf: String,
	pub fee_base_msat: u32,
	pub fee_proportional_millionths: u32,
	pub cltv_expiry_delta: u16,
}

impl GetInfo<RouteHopInfo> for RouteHop {
	fn get_info(&self, _network: Network) -> RouteHopInfo {
		let ssid_hex = &self.short_channel_id[..];
		let ssid = BigEndian::read_u64(&ssid_hex);
		RouteHopInfo {
			pubkey: self.pubkey.serialize()[..].into(),
			short_channel_id: ssid,
			short_channel_id_hex: ssid_hex.into(),
			short_channel_id_hrf: fmt_short_channel_id(ssid),
			fee_base_msat: self.fee_base_msat,
			fee_proportional_millionths: self.fee_proportional_millionths,
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
	pub fallback_addresses: Vec<Address>,
	#[serde(skip_serializing_if = "Vec::is_empty")]
	pub routes: Vec<Vec<RouteHopInfo>>,
	pub currency: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub amount_pico_btc: Option<u64>,

	// For signed invoices.
	pub signature: HexBytes,
	pub signature_recover_id: i32,
	pub payee_pubkey: Option<HexBytes>,
}

impl GetInfo<InvoiceInfo> for Invoice {
	fn get_info(&self, network: Network) -> InvoiceInfo {
		let signed_raw = self.clone().into_signed_raw();
		let (sig_rec, sig) = signed_raw.signature().0.serialize_compact();

		InvoiceInfo {
			timestamp: self.timestamp().clone().into(),
			payment_hash: sha256::Hash::from_slice(&self.payment_hash()[..]).unwrap(),
			description: match self.description() {
				InvoiceDescription::Direct(s) => s.clone().into_inner(),
				InvoiceDescription::Hash(h) => h.0.to_string(),
			},
			payee_pub_key: self.payee_pub_key().map(|pk| pk.serialize()[..].into()),
			expiry_time: Some(
				Local::now() + Duration::from_std(self.expiry_time()).expect("Invalid expiry"),
			),
			min_final_cltv_expiry: self.min_final_cltv_expiry().map(|e| *e),
			fallback_addresses: self
				.fallbacks()
				.iter()
				.map(|f| {
					//TODO(stevenroose) see https://github.com/rust-bitcoin/rust-lightning-invoice/issues/24
					Address {
						payload: match f {
							Fallback::PubKeyHash(pkh) => {
								Payload::PubkeyHash(Hash::from_slice(&pkh[..]).expect("wrong hash"))
							}
							Fallback::ScriptHash(sh) => {
								Payload::ScriptHash(Hash::from_slice(&sh[..]).expect("wrong hash"))
							}
							Fallback::SegWitProgram {
								version: v,
								program: p,
							} => Payload::WitnessProgram {
								version: WitnessVersion::try_from(v.to_u8())
									.expect("invalid segwit version"),
								program: p.to_vec(),
							},
						},
						network: network,
					}
				})
				.collect(),
			routes: self
				.routes()
				.iter()
				.map(|r| r.iter().map(|h| GetInfo::get_info(h, network)).collect())
				.collect(),
			currency: match self.currency() {
				Currency::Bitcoin => "bitcoin".to_owned(),
				Currency::BitcoinTestnet => "bitcoin-testnet".to_owned(),
				Currency::Regtest => "bitcoin-regtest".to_owned(),
				Currency::Simnet => "bitcoin-signet".to_owned(),
			},
			amount_pico_btc: self.amount_pico_btc(),
			signature: sig.as_ref().into(),
			signature_recover_id: sig_rec.to_i32(),
			payee_pubkey: signed_raw
				.recover_payee_pub_key()
				.ok()
				.map(|s| s.0.serialize().as_ref().into()),
		}
	}
}
