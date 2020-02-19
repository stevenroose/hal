use bitcoin::hashes::{sha256, sha256d};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct MessageHash {
	pub sha256: sha256::Hash,
	pub sha256d: sha256d::Hash,
	pub sign_hash: sha256d::Hash,
}
