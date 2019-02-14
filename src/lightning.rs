use bitcoin::{util::address::Payload, Address, Network};
use bitcoin_bech32::{constants::Network as B32Network, u5, WitnessProgram};
use chrono::{offset::Local, DateTime, Duration};
use lightning_invoice::{Currency, Fallback, Invoice, InvoiceDescription, RouteHop};

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct RouteHopInfo {
	pub pubkey: ::HexBytes,
	pub short_channel_id: ::HexBytes,
	pub fee_base_msat: u32,
	pub fee_proportional_millionths: u32,
	pub cltv_expiry_delta: u16,
}

impl ::GetInfo<RouteHopInfo> for RouteHop {
	fn get_info(&self, _network: Network) -> RouteHopInfo {
		RouteHopInfo {
			pubkey: self.pubkey.serialize()[..].into(),
			short_channel_id: self.short_channel_id[..].into(),
			fee_base_msat: self.fee_base_msat,
			fee_proportional_millionths: self.fee_proportional_millionths,
			cltv_expiry_delta: self.cltv_expiry_delta,
		}
	}
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct InvoiceInfo {
	pub timestamp: DateTime<Local>,
	pub payment_hash: String, //TODO(stevenroose) use bitcoin_hashes
	pub description: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub payee_pub_key: Option<::HexBytes>,
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
}

impl ::GetInfo<InvoiceInfo> for Invoice {
	fn get_info(&self, network: Network) -> InvoiceInfo {
		InvoiceInfo {
			timestamp: self.timestamp().clone().into(),
			//TODO(stevenroose) see https://github.com/rust-bitcoin/rust-lightning-invoice/issues/23
			payment_hash: format!("{:?}", self.payment_hash()),
			description: match self.description() {
				InvoiceDescription::Direct(s) => s.clone().into_inner(),
				//TODO(stevenroose) see https://github.com/rust-bitcoin/rust-lightning-invoice/issues/23
				InvoiceDescription::Hash(h) => format!("{:?}", h),
			},
			payee_pub_key: self.payee_pub_key().map(|pk| pk.serialize()[..].into()),
			expiry_time: self.expiry_time().map(|e| {
				let duration = Duration::from_std(*e.as_duration()).expect("invalid expiry");
				Local::now() + duration
			}),
			min_final_cltv_expiry: self.min_final_cltv_expiry().map(|e| e.0),
			fallback_addresses: self
				.fallbacks()
				.iter()
				.map(|f| {
					//TODO(stevenroose) see https://github.com/rust-bitcoin/rust-lightning-invoice/issues/24
					Address {
						payload: match f {
							Fallback::PubKeyHash(pkh) => Payload::PubkeyHash(pkh[..].into()),
							Fallback::ScriptHash(sh) => Payload::ScriptHash(sh[..].into()),
							Fallback::SegWitProgram {
								version: v,
								program: p,
							} => Payload::WitnessProgram(
								WitnessProgram::new(
									//TODO(stevenroose) remove after https://github.com/rust-bitcoin/rust-bech32-bitcoin/issues/21
									u5::try_from_u8(v.to_u8()).expect("invalid segwit version"),
									p.to_vec(),
									//TODO(stevenroose) see https://github.com/rust-bitcoin/rust-bech32-bitcoin/pull/18
									match network {
										Network::Bitcoin => B32Network::Bitcoin,
										Network::Testnet => B32Network::Testnet,
										Network::Regtest => B32Network::Regtest,
									},
								)
								.expect("invalid witness program"),
							),
						},
						network: network,
					}
				})
				.collect(),
			routes: self
				.routes()
				.iter()
				.map(|r| r.iter().map(|h| ::GetInfo::get_info(h, network)).collect())
				.collect(),
			currency: match self.currency() {
				Currency::Bitcoin => "bitcoin".to_owned(),
				Currency::BitcoinTestnet => "bitcoin-testnet".to_owned(),
			},
			amount_pico_btc: self.amount_pico_btc(),
		}
	}
}
