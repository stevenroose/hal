use bitcoin::PublicKey;
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct SignedMessageInfo {
	pub message: String,
	pub public_key: PublicKey,
	pub signature_der_hex: ::HexBytes,
	pub signature_der_base64: String,
	pub signature_compact_hex: ::HexBytes,
	pub signature_compact_base64: String,
}
