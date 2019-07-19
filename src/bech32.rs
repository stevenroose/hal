use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct Bech32Info {
	/// Human-readable part
	pub hrp: String,
	/// Data payload as vector
    #[serde(skip_serializing_if = "Option::is_none")]
	pub payload_bytes: Option<Vec<u8>>,
	/// Data payload as hex string
	#[serde(skip_serializing_if = "Option::is_none")]
	pub payload_hex: Option<::HexBytes>,
}
