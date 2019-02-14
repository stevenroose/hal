use bitcoin::{Address, Network};

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct DerivationInfo {
	pub network: Network,
	pub master_fingerprint: ::HexBytes,
	pub path: String,
	pub chain_code: ::HexBytes,
	pub identifier: ::HexBytes,
	pub fingerprint: ::HexBytes,
	pub public_key: ::HexBytes,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub secret_key: Option<String>,
	pub parent_fingerprint: ::HexBytes,
	#[serde(rename = "address-p2pkh")]
	pub address_p2pkh: Address,
	#[serde(rename = "address-p2wpkh")]
	pub address_p2wpkh: Address,
	#[serde(rename = "address-p2shwpkh")]
	pub address_p2shwpkh: Address,
}
