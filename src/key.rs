use bitcoin::{PrivateKey, PublicKey};
use serde::{Deserialize, Serialize};

use address;

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct KeyInfo {
	pub raw_private_key: ::HexBytes,
	pub wif_private_key: PrivateKey,
	pub public_key: PublicKey,
	pub uncompressed_public_key: PublicKey,
	pub addresses: address::Addresses,
}
