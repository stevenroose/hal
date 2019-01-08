use bitcoin;

use bitcoin::util::hash::BitcoinHash;

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct InputScriptInfo {
	pub hex: Option<::HexBytes>,
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
	pub witness: Option<Vec<::HexBytes>>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct OutputScriptInfo {
	pub hex: Option<::HexBytes>,
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
			address: ::address::address_from_script(
				&script,
				match testnet {
					false => bitcoin::Network::Bitcoin,
					true => bitcoin::Network::Testnet,
				},
			),
		}
	}
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
