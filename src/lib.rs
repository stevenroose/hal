#[macro_use]
extern crate serde_derive;
extern crate bitcoin;
extern crate hex;
extern crate serde;

use bitcoin::util::hash::BitcoinHash;

/// Utility struct to serialize byte strings as hex.
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
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
		use serde::de::Error;

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

impl InputScriptInfo {
	pub fn create(script: &bitcoin::Script) -> InputScriptInfo {
		InputScriptInfo {
			hex: Some(script.to_bytes().into()),
			asm: Some(format!("{:?}", script)), //TODO(stevenroose) asm
		}
	}
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

impl OutputScriptInfo {
	pub fn create(script: &bitcoin::Script, testnet: bool) -> OutputScriptInfo {
		OutputScriptInfo {
			hex: Some(script.to_bytes().into()),
			asm: Some(format!("{:?}", script)), //TODO(stevenroose) asm
			type_: Some(
				if script.is_p2pk() {
					"p2pk"
				} else if script.is_p2pkh() {
					"p2pkh"
				} else if script.is_op_return() {
					"opreturn"
				} else if script.is_p2sh() {
					"p2sh"
				} else if script.is_v0_p2wpkh() {
					"p2wpkh"
				} else if script.is_v0_p2wsh() {
					"p2wsh"
				} else {
					"unknown"
				}
				.to_owned(),
			),
			address: address_from_script(
				&script,
				match testnet {
					false => bitcoin::Network::Bitcoin,
					true => bitcoin::Network::Testnet,
				},
			),
		}
	}
}

/// convert Network to bech32 network (this should go away soon)
fn bech_network(network: bitcoin::Network) -> bitcoin_bech32::constants::Network {
	match network {
		bitcoin::Network::Bitcoin => bitcoin_bech32::constants::Network::Bitcoin,
		bitcoin::Network::Testnet => bitcoin_bech32::constants::Network::Testnet,
		bitcoin::Network::Regtest => bitcoin_bech32::constants::Network::Regtest,
	}
}

/// Retrieve an address from the given script.
pub fn address_from_script(
	script: &bitcoin::Script,
	network: bitcoin::Network,
) -> Option<bitcoin::util::address::Address> {
	Some(bitcoin::util::address::Address {
		payload: if script.is_p2sh() {
			bitcoin::util::address::Payload::ScriptHash(script.as_bytes()[2..22].into())
		} else if script.is_p2pkh() {
			bitcoin::util::address::Payload::PubkeyHash(script.as_bytes()[3..23].into())
		} else if script.is_p2pk() {
			let secp = secp256k1::Secp256k1::without_caps();
			match secp256k1::key::PublicKey::from_slice(
				&secp,
				&script.as_bytes()[1..(script.len() - 1)],
			) {
				Ok(pk) => bitcoin::util::address::Payload::Pubkey(pk),
				Err(_) => return None,
			}
		} else if script.is_v0_p2wsh() {
			match bitcoin_bech32::WitnessProgram::new(
				bitcoin_bech32::u5::try_from_u8(0).expect("0<32"),
				script.as_bytes()[2..34].to_vec(),
				bech_network(network),
			) {
				Ok(prog) => bitcoin::util::address::Payload::WitnessProgram(prog),
				Err(_) => return None,
			}
		} else if script.is_v0_p2wpkh() {
			match bitcoin_bech32::WitnessProgram::new(
				bitcoin_bech32::u5::try_from_u8(0).expect("0<32"),
				script.as_bytes()[2..22].to_vec(),
				bech_network(network),
			) {
				Ok(prog) => bitcoin::util::address::Payload::WitnessProgram(prog),
				Err(_) => return None,
			}
		} else {
			return None;
		},
		network: network,
	})
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct OutputInfo {
	pub value: Option<u64>,
	pub script_pub_key: Option<OutputScriptInfo>,
}

impl OutputInfo {
	pub fn create(output: &bitcoin::TxOut, testnet: bool) -> OutputInfo {
		OutputInfo {
			value: Some(output.value),
			script_pub_key: Some(OutputScriptInfo::create(&output.script_pubkey, testnet)),
		}
	}
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

impl TransactionInfo {
	pub fn create(tx: &bitcoin::Transaction, testnet: bool) -> TransactionInfo {
		TransactionInfo {
			txid: Some(tx.txid()),
			hash: Some(tx.bitcoin_hash()),
			version: Some(tx.version),
			locktime: Some(tx.lock_time),
			size: Some(bitcoin::consensus::encode::serialize(tx).len()),
			weight: Some(tx.get_weight() as usize),
			vsize: Some((tx.get_weight() / 4) as usize),
			inputs: Some(
				tx.input
					.iter()
					.map(|input| InputInfo {
						prevout: Some(input.previous_output.to_string()),
						txid: Some(input.previous_output.txid),
						vout: Some(input.previous_output.vout),
						sequence: Some(input.sequence),
						script_sig: Some(InputScriptInfo::create(&input.script_sig)),
						witness: if input.witness.len() > 0 {
							Some(input.witness.iter().map(|h| h.clone().into()).collect())
						} else {
							None
						},
					})
					.collect(),
			),
			outputs: Some(
				tx.output.iter().map(|output| OutputInfo::create(&output, testnet)).collect(),
			),
		}
	}
}
