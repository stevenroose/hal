
#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate hex;
extern crate bitcoin;

/// Utility struct to serialize byte strings as hex.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HexBytes(pub Vec<u8>);

impl From<Vec<u8>> for HexBytes {
	fn from(vec: Vec<u8>) -> HexBytes {
		HexBytes(vec)
	}
}

impl From<&[u8]> for HexBytes {
	fn from(slice: &[u8]) -> HexBytes {
		HexBytes(slice.to_vec())
	}
}

impl ::serde::Serialize for HexBytes {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
		s.serialize_str(&hex::encode(&self.0))
    }
}

impl<'de> ::serde::Deserialize<'de> for HexBytes {
    fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<HexBytes, D::Error> {
        use ::serde::de::Error;

		let hex_str: String = ::serde::Deserialize::deserialize(d)?;
		Ok(HexBytes(hex::decode(hex_str).map_err(D::Error::custom)?))
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct AddressInfo {
	pub network: bitcoin::Network,
	#[serde(rename = "type")]
	pub type_: Option<String>,
	pub script_pub_key: OutputScriptInfo,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub witness_program_version: Option<usize>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub pubkey_hash: Option<HexBytes>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub script_hash: Option<HexBytes>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct InputScriptInfo {
	pub hex: Option<HexBytes>,
	pub asm: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct InputInfo {
	pub prevout: Option<String>,
	pub txid: Option<bitcoin::util::hash::Sha256dHash>,
	pub vout: Option<u32>,
	pub script_sig: Option<InputScriptInfo>,
	pub sequence: Option<u32>,
	pub witness: Option<Vec<HexBytes>>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct OutputScriptInfo {
	pub hex: Option<HexBytes>,
	pub asm: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none", rename = "type")]
	pub type_: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub address: Option<bitcoin::Address>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct OutputInfo {
	pub value: Option<u64>,
	pub script_pub_key: Option<OutputScriptInfo>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct TransactionInfo {
	pub txid: Option<bitcoin::util::hash::Sha256dHash>,
	pub hash: Option<bitcoin::util::hash::Sha256dHash>,
	pub size: Option<usize>,
	pub weight: Option<usize>,
	pub vsize: Option<usize>,
	pub version: Option<u32>,
	pub locktime: Option<u32>,
	pub inputs: Option<Vec<InputInfo>>,
	pub outputs: Option<Vec<OutputInfo>>,
}
