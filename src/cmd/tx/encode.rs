use std::io::Write;

use hal;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	clap::SubCommand::with_name("encode")
		.about("encode a raw transaction from JSON")
		.args(&[
			clap::Arg::with_name("tx-info")
				.help("the transaction info in JSON")
				.takes_value(true)
				.required(true),
			clap::Arg::with_name("raw-stdout")
				.long("raw")
				.short("r")
				.help("output the raw bytes of the result to stdout")
				.required(false),
		])
}

/// Check both ways to specify the outpoint and panic if conflicting.
fn outpoint_from_input_info(input: &hal::tx::InputInfo) -> bitcoin::OutPoint {
	let op1 = input.prevout.as_ref().map(|ref op| op.parse().expect("invalid prevout format"));
	let op2 = match input.txid {
		Some(txid) => match input.vout {
			Some(vout) => Some(bitcoin::OutPoint {
				txid: txid,
				vout: vout,
			}),
			None => panic!("\"txid\" field given in input without \"vout\" field"),
		},
		None => None,
	};

	match (op1, op2) {
		(Some(op1), Some(op2)) => {
			if op1 != op2 {
				panic!("Conflicting prevout information in input.");
			}
			op1
		}
		(Some(op), None) => op,
		(None, Some(op)) => op,
		(None, None) => panic!("No previous output provided in input."),
	}
}

fn encode_script_sig(ss: hal::tx::InputScriptInfo) -> bitcoin::Script {
	if let Some(hex) = ss.hex {
		if ss.asm.is_some() {
			warn!("Field \"asm\" of input is ignored.");
		}

		hex.0.into()
	} else if let Some(_) = ss.asm {
		panic!("Decoding script assembly is not yet supported.");
	} else {
		panic!("No scriptSig info provided.");
	}
}

fn encode_input(input: hal::tx::InputInfo) -> bitcoin::TxIn {
	bitcoin::TxIn {
		previous_output: outpoint_from_input_info(&input),
		script_sig: encode_script_sig(
			input.script_sig.expect("Field \"scriptSig\" is required for inputs."),
		),
		sequence: input.sequence.expect("Field \"sequence\" is required for inputs."),
		witness: match input.witness {
			Some(ref w) => w.iter().map(|h| h.clone().0).collect(),
			None => Vec::new(),
		},
	}
}

fn encode_script_pubkey(
	spk: hal::tx::OutputScriptInfo,
	used_network: &mut Option<bitcoin::Network>,
) -> bitcoin::Script {
	if spk.type_.is_some() {
		warn!("Field \"type\" of output is ignored.");
	}

	if let Some(hex) = spk.hex {
		if spk.asm.is_some() {
			warn!("Field \"asm\" of output is ignored.");
		}
		if spk.address.is_some() {
			warn!("Field \"address\" of output is ignored.");
		}

		//TODO(stevenroose) do script sanity check to avoid blackhole?
		hex.0.into()
	} else if let Some(_) = spk.asm {
		if spk.address.is_some() {
			warn!("Field \"address\" of output is ignored.");
		}

		panic!("Decoding script assembly is not yet supported.");
	} else if let Some(address) = spk.address {
		// Error if another network had already been used.
		if used_network.replace(address.network).unwrap_or(address.network) != address.network {
			panic!("Addresses for different networks are used in the output scripts.");
		}

		address.script_pubkey()
	} else {
		panic!("No scriptPubKey info provided.");
	}
}

fn encode_output(output: hal::tx::OutputInfo) -> bitcoin::TxOut {
	// Keep track of which network has been used in addresses and error if two different networks
	// are used.
	let mut used_network = None;

	bitcoin::TxOut {
		value: output.value.expect("Field \"value\" is required for outputs."),
		script_pubkey: encode_script_pubkey(
			output.script_pub_key.expect("Field \"scriptPubKey\" is required for outputs."),
			&mut used_network,
		),
	}
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	let json_tx = matches.value_of("tx-info").expect("no JSON tx info provided");
	let info: hal::tx::TransactionInfo = serde_json::from_str(json_tx).expect("invalid JSON");

	// Fields that are ignored.
	if info.txid.is_some() {
		warn!("Field \"txid\" is ignored.");
	}
	if info.hash.is_some() {
		warn!("Field \"hash\" is ignored.");
	}
	if info.size.is_some() {
		warn!("Field \"size\" is ignored.");
	}
	if info.weight.is_some() {
		warn!("Field \"weight\" is ignored.");
	}
	if info.vsize.is_some() {
		warn!("Field \"vsize\" is ignored.");
	}

	let tx = bitcoin::Transaction {
		version: info.version.expect("Field \"version\" is required."),
		lock_time: info.locktime.expect("Field \"locktime\" is required."),
		input: info
			.inputs
			.expect("Field \"inputs\" is required.")
			.into_iter()
			.map(encode_input)
			.collect(),
		output: info
			.outputs
			.expect("Field \"outputs\" is required.")
			.into_iter()
			.map(encode_output)
			.collect(),
	};

	let tx_bytes = bitcoin::consensus::encode::serialize(&tx);
	if matches.is_present("raw-stdout") {
		::std::io::stdout().write_all(&tx_bytes).unwrap();
	} else {
		print!("{}", hex::encode(&tx_bytes));
	}
}
