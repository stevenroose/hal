use serde::{Deserialize, Serialize};

use crate::HexBytes;

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct Bech32Info {
	/// Bech32 encoded string
	pub bech32: String,
	/// Human-readable part
	pub hrp: String,
	/// Hex-encoded data payload in base32
	pub payload: HexBytes,
	/// Hex-encoded data payload in base256
	#[serde(skip_serializing_if = "Option::is_none")]
	pub payload_bytes: Option<HexBytes>,
}
