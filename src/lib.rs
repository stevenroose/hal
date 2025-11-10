extern crate bip39 as bip39lib;
extern crate bitcoin;
extern crate byteorder;
extern crate chrono;
extern crate hex;
#[macro_use]
extern crate lazy_static;
extern crate lightning_invoice;
extern crate miniscript as miniscriptlib;
extern crate secp256k1;
extern crate serde;

pub mod address;
pub mod ark;
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
mod serde_utils;
pub use serde_utils::HexBytes;

use bitcoin::Network;

lazy_static! {
	/// A global secp256k1 context.
	pub static ref SECP: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}


/// Get JSON-able objects that describe the type.
pub trait GetInfo<T: ::serde::Serialize> {
	/// Get a description of this object given the network of interest.
	fn get_info(&self, network: Network) -> T;
}
