use bitcoin::consensus;
use clap;

use hal;

use bitcoin::BitcoinHash;
use bitcoin::Script;
use bitcoin::Transaction;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	clap::SubCommand::with_name("decode")
		.about("decode a raw transaction to JSON")
		.arg(
			clap::Arg::with_name("raw-tx")
				.help("the raw transaction in hex")
				.takes_value(true)
				.required(true),
		)
		.arg(
			// This influences the addresses we print.
			clap::Arg::with_name("testnet")
				.long("testnet")
				.help("for testnet transaction")
				.takes_value(true)
				.required(false),
		)
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
	script: &Script,
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

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	let hex_tx = matches.value_of("raw-tx").expect("no raw tx provided");
	let raw_tx = hex::decode(hex_tx).expect("could not decode raw tx");
	let tx: Transaction = consensus::encode::deserialize(&raw_tx).expect("invalid tx format");

	let info = hal::TransactionInfo {
		txid: Some(tx.txid()),
		hash: Some(tx.bitcoin_hash()),
		version: Some(tx.version),
		locktime: Some(tx.lock_time),
		size: Some(raw_tx.len()),
		weight: Some(tx.get_weight() as usize),
		vsize: Some((tx.get_weight() / 4) as usize),
		inputs: Some(
			tx.input
				.iter()
				.map(|input| hal::InputInfo {
					prevout: Some(input.previous_output.to_string()),
					txid: Some(input.previous_output.txid),
					vout: Some(input.previous_output.vout),
					sequence: Some(input.sequence),
					script_sig: Some(hal::InputScriptInfo {
						hex: Some(input.script_sig.to_bytes().into()),
						asm: Some(format!("{:?}", input.script_sig)), //TODO(stevenroose) asm
					}),
					witness: if input.witness.len() > 0 {
						Some(input.witness.iter().map(|h| h.clone().into()).collect())
					} else {
						None
					},
				})
				.collect(),
		),
		outputs: Some(
			tx.output
				.iter()
				.map(|output| hal::OutputInfo {
					value: Some(output.value),
					script_pub_key: Some(hal::OutputScriptInfo {
						hex: Some(output.script_pubkey.to_bytes().into()),
						asm: Some(format!("{:?}", output.script_pubkey)), //TODO(stevenroose) asm
						type_: Some(
							if output.script_pubkey.is_p2pk() {
								"p2pk"
							} else if output.script_pubkey.is_p2pkh() {
								"p2pkh"
							} else if output.script_pubkey.is_op_return() {
								"opreturn"
							} else if output.script_pubkey.is_p2sh() {
								"p2sh"
							} else if output.script_pubkey.is_v0_p2wpkh() {
								"p2wpkh"
							} else if output.script_pubkey.is_v0_p2wsh() {
								"p2wsh"
							} else {
								"unknown"
							}
							.to_owned(),
						),
						address: address_from_script(
							&output.script_pubkey,
							match matches.is_present("testnet") {
								false => bitcoin::Network::Bitcoin,
								true => bitcoin::Network::Testnet,
							},
						),
					}),
				})
				.collect(),
		),
	};

	serde_json::to_writer_pretty(::std::io::stdout(), &info).unwrap();
}
