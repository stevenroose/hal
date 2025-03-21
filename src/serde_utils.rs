
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub mod network_kind {
	use super::*;
    use bitcoin::NetworkKind;

	pub fn serialize<S: ::serde::Serializer>(network: &NetworkKind, s: S) -> Result<S::Ok, S::Error> {
		match network {
			NetworkKind::Main => s.serialize_str("main"),
			NetworkKind::Test => s.serialize_str("test"),
		}
	}

	pub fn deserialize<'de, D: ::serde::Deserializer<'de>>(d: D) -> Result<NetworkKind, D::Error> {
		use serde::de::Error;

		match <&str>::deserialize(d)? {
			"main" => Ok(NetworkKind::Main),
			"test" => Ok(NetworkKind::Test),
			k => Err(D::Error::custom(format!("unknown network kind: {}", k))),
		}
	}
}

/// Utility struct to serialize byte strings as hex.
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct HexBytes(pub Vec<u8>);

impl HexBytes {
	pub fn hex(&self) -> String {
		hex::encode(&self.0)
	}

	pub fn bytes(&self) -> &[u8] {
		&self.0
	}

	pub fn take_bytes(self) -> Vec<u8> {
		self.0
	}
}

impl From<Vec<u8>> for HexBytes {
	fn from(vec: Vec<u8>) -> HexBytes {
		HexBytes(vec)
	}
}

impl<'a> From<&'a [u8]> for HexBytes {
	fn from(slice: &'a [u8]) -> HexBytes {
		HexBytes(slice.to_vec())
	}
}

impl Serialize for HexBytes {
	fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
		s.serialize_str(&hex::encode(&self.0))
	}
}

impl<'de> Deserialize<'de> for HexBytes {
	fn deserialize<D: Deserializer<'de>>(d: D) -> Result<HexBytes, D::Error> {
		use serde::de::Error;

		let hex_str = <&str>::deserialize(d)?;
		Ok(HexBytes(hex::decode(hex_str).map_err(D::Error::custom)?))
	}
}
