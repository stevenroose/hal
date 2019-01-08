use bitcoin;

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct AddressInfo {
	pub network: bitcoin::Network,
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
