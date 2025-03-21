use serde::{Deserialize, Serialize};

use crate::HexBytes;

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct Bech32Info {
	/// Bech32 encoded string
	pub bech32: String,
	/// Human-readable part
	pub hrp: String,
	/// Hex-encoded data payload
	pub payload: HexBytes,
}
