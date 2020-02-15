extern crate bip39 as bip39lib;
extern crate bitcoin;
extern crate byteorder;
extern crate chrono;
extern crate hex;
extern crate lightning_invoice;
extern crate miniscript as miniscriptlib;
extern crate secp256k1;
extern crate serde;

pub mod address;
pub mod bech32;
pub mod bip32;
pub mod bip39;
pub mod block;
pub mod key;
pub mod lightning;
pub mod message;
pub mod miniscript;
pub mod psbt;
pub mod tx;

use bitcoin::Network;

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

impl ::serde::Serialize for HexBytes {
	fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
		s.serialize_str(&hex::encode(&self.0))
	}
}

impl<'de> ::serde::Deserialize<'de> for HexBytes {
	fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<HexBytes, D::Error> {
		use serde::de::Error;

		let hex_str: String = ::serde::Deserialize::deserialize(d)?;
		Ok(HexBytes(hex::decode(hex_str).map_err(D::Error::custom)?))
	}
}

/// Get JSON-able objects that describe the type.
pub trait GetInfo<T: ::serde::Serialize> {
	/// Get a description of this object given the network of interest.
	fn get_info(&self, network: Network) -> T;
}
