use bitcoin::{Network, Script, Address, util::address::Payload};

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct AddressInfo {
	pub network: Network,
	#[serde(rename = "type")]
	pub type_: Option<String>,
	pub script_pub_key: ::tx::OutputScriptInfo,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub witness_program_version: Option<usize>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub pubkey_hash: Option<::HexBytes>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub script_hash: Option<::HexBytes>,
}

/// convert Network to bech32 network (this should go away soon)
fn bech_network(network: Network) -> bitcoin_bech32::constants::Network {
	match network {
		Network::Bitcoin => bitcoin_bech32::constants::Network::Bitcoin,
		Network::Testnet => bitcoin_bech32::constants::Network::Testnet,
		Network::Regtest => bitcoin_bech32::constants::Network::Regtest,
	}
}

/// Retrieve an address from the given script.
pub fn address_from_script(
	script: &Script,
	network: Network,
) -> Option<Address> {
	Some(Address {
		payload: if script.is_p2sh() {
			Payload::ScriptHash(script.as_bytes()[2..22].into())
		} else if script.is_p2pkh() {
			Payload::PubkeyHash(script.as_bytes()[3..23].into())
		} else if script.is_p2pk() {
			match secp256k1::key::PublicKey::from_slice(&script.as_bytes()[1..(script.len() - 1)]) {
				Ok(pk) => Payload::Pubkey(pk),
				Err(_) => return None,
			}
		} else if script.is_v0_p2wsh() {
			match bitcoin_bech32::WitnessProgram::new(
				bitcoin_bech32::u5::try_from_u8(0).expect("0<32"),
				script.as_bytes()[2..34].to_vec(),
				bech_network(network),
			) {
				Ok(prog) => Payload::WitnessProgram(prog),
				Err(_) => return None,
			}
		} else if script.is_v0_p2wpkh() {
			match bitcoin_bech32::WitnessProgram::new(
				bitcoin_bech32::u5::try_from_u8(0).expect("0<32"),
				script.as_bytes()[2..22].to_vec(),
				bech_network(network),
			) {
				Ok(prog) => Payload::WitnessProgram(prog),
				Err(_) => return None,
			}
		} else {
			return None;
		},
		network: network,
	})
}

#[derive(Clone, PartialEq, Eq, Debug, Default, Deserialize, Serialize)]
pub struct CreatedAddresses {
	#[serde(skip_serializing_if = "Option::is_none")]
	pub p2pkh: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub p2wpkh: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub p2shwpkh: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub p2sh: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub p2wsh: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub p2shwsh: Option<String>,
}
