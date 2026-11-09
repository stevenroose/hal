use std::io::Write;

use bitcoin::address::NetworkUnchecked;
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::blockdata::transaction;
use bitcoin::hashes::Hash;
use bitcoin::sighash::{Annex, Prevouts, SighashCache};
use bitcoin::taproot::{LeafVersion, TapLeafHash};
use bitcoin::{Address, Network, OutPoint, ScriptBuf, Transaction, TxIn, TxOut};

use hal::tx::{
	InputInfo, InputScriptInfo, OutputInfo, OutputScriptInfo, SighashInfo, TransactionInfo,
};
use crate::prelude::*;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("tx", "manipulate transactions")
		.subcommand(cmd_create())
		.subcommand(cmd_decode())
		.subcommand(cmd_sighash())
		.subcommands(cmd_verify())
}

pub fn execute<'a>(args: &clap::ArgMatches<'a>) {
	match args.subcommand() {
		("create", Some(ref m)) => exec_create(&m),
		("decode", Some(ref m)) => exec_decode(&m),
		("sighash", Some(ref m)) => exec_sighash(&m),
		#[cfg(feature = "bitcoinconsensus")]
		("verify", Some(ref m)) => exec_verify(&m),
		(_, _) => unreachable!("clap prints help"),
	};
}

fn cmd_create<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("create", "create a raw transaction from JSON")
		.arg(args::arg("tx-info", "the transaction info in JSON; If omitted, reads from stdin.")
			.required(false))
		.arg(args::flag("raw-stdout", "output the raw bytes of the result to stdout")
			.short("r"))
		.long_about(r#"
Create a transaction from JSON. Use the same format as the `hal tx decode` output.

It's possible to pass the JSON string as the first argument or pass it via stdin.

Example format:
{
  "version": 1,
  "locktime": 0,
  "inputs": [
    {
      "prevout": "78a0f5b35b73f1f6e054274aa3904867774600f09bd194e97e7a0fd953b27c54:6",
      "script_sig": {
        "hex":
"483045022100fad8d9b44d1d3a86bd9719ef642b32ed0a1c8f4e3de4e2009936988f73f12ad702207a2204cbdfd166d099cbb08e6c7886db5b986ef4fdfee383c1b8fc4df82ecea80121030a696d89d161c086586cf0de7d98fb97181a1ee0265130f7ddbecd17d616c780"
      },
      "sequence": 4294967295
    },
    {
      "txid": "c182fa9182957c5b906fd2b339d7a01dd110340bced99e049e2bd2c135f4513a",
      "vout": 1,
      "script_sig": {
        "hex": "220020fa28dc1e5eb222055e90f8cade9bcd13ca9ddab7a5ed029e27d41a736f7455ce"
      },
      "sequence": 4294967294,
      "witness": [
        "",
        "30440220725e1c098d85013166fae52794811f6531ff3962ea6bc3228ecfdd4699ae669b022064d5c88f2b838968a345681bbfeb2c09f0433ece511bc4d139c4805adf59d74601",
        "3044022055aa0f675bf0c21e113527f838b93d5922143ae6e52b094416d44551ff6d236202205ef3773cc9a7fe2076310c92adc73670747309265ecedb0cffe194885a89863601",
        "5221027111c0d6cbc3a40c6e6197ed234bd6e59f277c88094fd33297b1e0a3787a5b7d2102e71711c9840d68e6401d4bd5df78f1850e25ae41f082f4b38ceec37d60cab5442103eeae18900c0d12046f644b960a1ef84589f7f4f71d07914006d550bf85c576e153ae"
      ]
    }
  ],
  "outputs": [
    {
      "value": 500000,
      "script_pub_key": {
        "hex": "a91405394a3a5dedce4f945ed9f650fa9ff23f011d4687"
      }
    },
    {
      "value": 2590000,
      "script_pub_key": {
        "address": "34nFYcfPNTuWCV76YrwdVc4MyXmeVMMpsZ"
      }
    }
  ]
}"#
	)
}

/// Check both ways to specify the outpoint and panic if conflicting.
fn outpoint_from_input_info(input: &InputInfo) -> OutPoint {
	let prevout: Option<OutPoint> = input.prevout.as_ref().map(
		|ref op| op.parse().need("invalid prevout format")
	);
	let txid = input.txid;
	let vout = input.vout;

	match (prevout, txid, vout) {
		(Some(p), Some(t), _) if t != p.txid => exit!("prevout and txid don't match"),
		(Some(p), _, Some(v)) if v != p.vout => exit!("prevout and vout don't match"),
		(Some(p), _, _) => p,
		(None, Some(t), Some(v)) => OutPoint::new(t, v),
		_ => exit!("inputs should specify either the prevout or both the txid and vout"),
	}
}

fn create_script_sig(ss: InputScriptInfo) -> ScriptBuf {
	if let Some(hex) = ss.hex {
		if ss.asm.is_some() {
			warn!("Field \"asm\" of input is ignored.");
		}

		hex.0.into()
	} else if let Some(_) = ss.asm {
		exit!("Decoding script assembly is not yet supported.");
	} else {
		exit!("No scriptSig info provided.");
	}
}

fn create_input(input: InputInfo) -> TxIn {
	if input.is_rbf.is_some() {
		warn!("Field \"is_rbf\" of input is ignored.");
	}
	if input.relative_locktime.is_some() {
		warn!("Field \"relative_locktime\" of input is ignored.");
	}
	if input.tapscript.is_some() {
		warn!("Field \"tapscript\" of input is ignored.");
	}
	if input.taproot_control_block.is_some() {
		warn!("Field \"taproot_control_block\" of input is ignored.");
	}
	if input.taproot_annex.is_some() {
		warn!("Field \"taproot_annex\" of input is ignored.");
	}
	TxIn {
		previous_output: outpoint_from_input_info(&input),
		script_sig: input.script_sig.map(create_script_sig).unwrap_or_default(),
		sequence: bitcoin::Sequence::from_consensus(input.sequence.unwrap_or_default()),
		witness: match input.witness {
			Some(ref w) => bitcoin::Witness::from_slice(&w.iter().map(|h| &h.0).collect::<Vec<_>>()),
			None => bitcoin::Witness::new(),
		},
	}
}

/// We use this type to track possible networks used by the user.
pub struct UsedNetwork {
	possible: Vec<Network>,
}

impl UsedNetwork {
	pub fn new(network: Option<Network>) -> UsedNetwork {
		UsedNetwork {
			possible: match network {
				Some(n) => vec![n],
				None => vec![
					Network::Bitcoin,
					Network::Testnet,
					Network::Testnet4,
					Network::Signet,
					Network::Regtest,
				],
			},
		}
	}

	fn register_addr(&mut self, addr: &Address<NetworkUnchecked>) {
		self.possible.retain(|n| addr.is_valid_for_network(*n));
		if self.possible.is_empty() {
			exit!("incompatible use of networks in addresses: {:?}", addr);
		}
	}
}

fn create_script_pubkey(spk: OutputScriptInfo, used_network: &mut UsedNetwork) -> ScriptBuf {
	if spk.type_.is_some() {
		warn!("Field \"type\" of output is ignored.");
	}

	// First check consistency of the address, if given.
	if let Some(ref addr) = spk.address {
		// Error if another network had already been used.
		used_network.register_addr(addr);
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

		//TODO(stevenroose) support script disassembly
		exit!("Decoding script assembly is not yet supported.");
	} else if let Some(address) = spk.address {
		address.assume_checked().script_pubkey()
	} else {
		exit!("No scriptPubKey info provided.");
	}
}

fn create_output(output: OutputInfo, used_network: &mut UsedNetwork) -> TxOut {
	TxOut {
		value: output.value.need("Field \"value\" is required for outputs."),
		script_pubkey: output
			.script_pub_key
			.map(|s| create_script_pubkey(s, used_network))
			.unwrap_or_default(),
	}
}

pub fn create_transaction(info: TransactionInfo, used_network: &mut UsedNetwork) -> Transaction {
	// Fields that are ignored.
	if info.txid.is_some() {
		warn!("Field \"txid\" is ignored.");
	}
	if info.wtxid.is_some() {
		warn!("Field \"wtxid\" is ignored.");
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
	if info.base_size.is_some() {
		warn!("Field \"base_size\" is ignored.");
	}
	if info.locktime_type.is_some() {
		warn!("Field \"locktime_type\" is ignored.");
	}
	if info.locktime_enabled.is_some() {
		warn!("Field \"locktime_enabled\" is ignored.");
	}
	if info.is_coinbase.is_some() {
		warn!("Field \"is_coinbase\" is ignored.");
	}
	if info.is_explicitly_rbf.is_some() {
		warn!("Field \"is_explicitly_rbf\" is ignored.");
	}

	Transaction {
		version: transaction::Version(info.version.need("Field \"version\" is required.")),
		lock_time: bitcoin::absolute::LockTime::from_height(
			info.locktime.need("Field \"locktime\" is required.")
		).need("Field \"lockime\" is invalid").into(),
		input: info
			.inputs
			.need("Field \"inputs\" is required.")
			.into_iter()
			.map(create_input)
			.collect(),
		output: {
			info.outputs.need("Field \"outputs\" is required.")
			.into_iter().map(|o| create_output(o, used_network))
			.collect()
		},
	}
}

fn exec_create<'a>(args: &clap::ArgMatches<'a>) {
	let info = serde_json::from_str::<TransactionInfo>(&util::arg_or_stdin(args, "tx-info"))
		.need("invalid JSON provided");

	let mut used_network = UsedNetwork::new(args.explicit_network());
	let tx = create_transaction(info, &mut used_network);
	let tx_bytes = serialize(&tx);
	if args.is_present("raw-stdout") {
		::std::io::stdout().write_all(&tx_bytes).unwrap();
	} else {
		print!("{}", hex::encode(&tx_bytes));
	}
}

fn cmd_decode<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("decode", "decode a raw transaction to JSON")
		.arg(args::arg("raw-tx", "the raw transaction in hex").required(false))
}

fn exec_decode<'a>(args: &clap::ArgMatches<'a>) {
	let hex_tx = util::arg_or_stdin(args, "raw-tx");
	let raw_tx = hex::decode(hex_tx.as_ref()).need("could not decode raw tx");
	let tx: Transaction = deserialize(&raw_tx).need("invalid tx format");

	let info = hal::GetInfo::get_info(&tx, args.network());
	args.print_output(&info)
}

fn cmd_sighash<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("sighash", "calculate the signature hash of a transaction input")
		.arg(args::arg("raw-tx", "the raw transaction in hex").required(true))
		.arg(args::opt("input-idx", "the index of the input to calculate the sighash for")
			.required(true))
		.arg(args::opt("prevouts", "the outputs being spent, as comma-separated serialized \
			txouts in hex, in input order; for taproot all of them are needed unless \
			ANYONECANPAY is used, otherwise only the one being spent is used")
			.required(true))
		.arg(args::opt("sighash-type", "the sighash type, e.g. ALL, NONE|ANYONECANPAY or \
			DEFAULT for taproot; defaults to ALL or DEFAULT for taproot"))
		.arg(args::opt("redeem-script", "the redeem script in hex, for p2sh inputs"))
		.arg(args::opt("witness-script", "the witness script in hex, for p2wsh inputs"))
		.arg(args::opt("tapscript", "the leaf script in hex, for taproot script-path spends"))
		.arg(args::opt("leaf-version", "the leaf version of the tapscript (default 0xc0)"))
		.arg(args::opt("annex", "the taproot annex in hex, including the 0x50 prefix"))
		.long_about(r#"
Calculate the signature hash of a transaction input.

The type of the output being spent determines the kind of signature hash:
- p2pk, p2pkh and bare scripts: legacy, using the scriptPubkey as script code
- p2sh: legacy, using the redeem script as script code; when the redeem
  script is p2wpkh or p2wsh, the segwit v0 signature hash is calculated
- p2wpkh and p2wsh: segwit v0 (BIP-143)
- p2tr: taproot (BIP-341) key-path spend, or script-path spend when a
  tapscript is given

The resulting sighash is printed as raw bytes, so it can be passed directly
to `hal key ecdsa-sign` or `hal key schnorr-sign` without --reverse.
"#)
}

fn exec_sighash<'a>(args: &clap::ArgMatches<'a>) {
	let hex_tx = args.value_of("raw-tx").need("no raw tx provided");
	let raw_tx = hex::decode(hex_tx).need("could not decode raw tx");
	let tx: Transaction = deserialize(&raw_tx).need("invalid tx format");

	let idx = args.value_of("input-idx").need("no input index provided")
		.parse::<usize>().need("invalid input index");
	if idx >= tx.input.len() {
		exit!("input index out of range: tx has {} inputs", tx.input.len());
	}

	let prevouts = args.value_of("prevouts").need("no prevouts provided")
		.split(",")
		.map(|h| {
			let raw = hex::decode(h).need("invalid prevout hex");
			deserialize::<TxOut>(&raw).need("invalid prevout txout format")
		})
		.collect::<Vec<_>>();

	let opt_script = |name: &str| args.value_of(name).map(|h| {
		ScriptBuf::from_bytes(hex::decode(h).need(&format!("invalid {} hex", name)))
	});
	let redeem_script = opt_script("redeem-script");
	let witness_script = opt_script("witness-script");
	let tapscript = opt_script("tapscript");

	let mut cache = SighashCache::new(&tx);
	let sht_str = args.value_of("sighash-type");

	// Taproot.
	if prevouts.len() == 1 && prevouts[0].script_pubkey.is_p2tr() || prevouts.len() > idx
		&& prevouts.len() == tx.input.len() && prevouts[idx].script_pubkey.is_p2tr()
	{
		let sighash_type = match sht_str {
			Some(s) => hal::tx::parse_tap_sighash_type(s).need("invalid taproot sighash type"),
			None => bitcoin::TapSighashType::Default,
		};
		let prevouts = if prevouts.len() == tx.input.len() {
			Prevouts::All(&prevouts)
		} else if prevouts.len() == 1 {
			Prevouts::One(idx, prevouts[0].clone())
		} else {
			exit!("for taproot, provide either all prevouts or only the one being spent");
		};
		let annex = args.value_of("annex").map(|h| hex::decode(h).need("invalid annex hex"));
		let annex = annex.as_ref().map(|a| Annex::new(a).need("invalid annex"));
		let leaf_hash = tapscript.as_ref().map(|script| {
			let version = match args.value_of("leaf-version") {
				Some(v) => {
					let v = v.trim_start_matches("0x");
					let v = u8::from_str_radix(v, 16).need("invalid leaf version hex");
					LeafVersion::from_consensus(v).need("invalid leaf version")
				},
				None => LeafVersion::TapScript,
			};
			TapLeafHash::from_script(script, version)
		});
		let sighash = cache.taproot_signature_hash(
			idx, &prevouts, annex, leaf_hash.map(|h| (h, 0xffffffff)), sighash_type,
		).need("error calculating taproot sighash");
		args.print_output(&SighashInfo {
			sighash: sighash.to_byte_array()[..].into(),
			type_: if leaf_hash.is_some() {
				"taproot_script_spend".to_owned()
			} else {
				"taproot_key_spend".to_owned()
			},
			sighash_type: sighash_type.to_string(),
			input_index: idx,
			script_code: None,
			leaf_hash: leaf_hash,
		});
		return;
	}

	// Legacy and segwit v0 only need the prevout being spent.
	let prevout = if prevouts.len() == tx.input.len() {
		&prevouts[idx]
	} else if prevouts.len() == 1 {
		&prevouts[0]
	} else {
		exit!("provide either all prevouts or only the one being spent");
	};
	let sighash_type = match sht_str {
		Some(s) => hal::tx::parse_ecdsa_sighash_type(s).need("invalid ECDSA sighash type"),
		None => bitcoin::EcdsaSighashType::All,
	};

	// Determine the script that is actually being executed.
	let spk = &prevout.script_pubkey;
	let executed: ScriptBuf = if spk.is_p2sh() {
		let redeem = redeem_script.need("--redeem-script is required for p2sh inputs");
		if redeem.to_p2sh() != *spk {
			exit!("redeem script doesn't match the p2sh scriptPubkey");
		}
		redeem
	} else {
		spk.clone()
	};

	let (sighash, type_, script_code) = if executed.is_p2wpkh() {
		let script_code = executed.p2wpkh_script_code().unwrap();
		let sighash = cache.p2wpkh_signature_hash(idx, &executed, prevout.value, sighash_type)
			.need("error calculating segwit v0 sighash");
		(sighash.to_byte_array(), "segwit_v0", script_code)
	} else if executed.is_p2wsh() {
		let ws = witness_script.need("--witness-script is required for p2wsh inputs");
		if ws.to_p2wsh() != executed {
			exit!("witness script doesn't match the p2wsh scriptPubkey");
		}
		let sighash = cache.p2wsh_signature_hash(idx, &ws, prevout.value, sighash_type)
			.need("error calculating segwit v0 sighash");
		(sighash.to_byte_array(), "segwit_v0", ws)
	} else if executed.is_witness_program() {
		exit!("unsupported witness program version");
	} else {
		let sighash = cache.legacy_signature_hash(idx, &executed, sighash_type.to_u32())
			.need("error calculating legacy sighash");
		(sighash.to_byte_array(), "legacy", executed)
	};

	args.print_output(&SighashInfo {
		sighash: sighash[..].into(),
		type_: type_.to_owned(),
		sighash_type: sighash_type.to_string(),
		input_index: idx,
		script_code: Some(script_code.into_bytes().into()),
		leaf_hash: None,
	});
}

/// The verify command, only available with the bitcoinconsensus feature.
#[cfg(feature = "bitcoinconsensus")]
fn cmd_verify<'a>() -> Vec<clap::App<'a, 'a>> {
	vec![
		cmd::subcommand("verify", "verify the scripts of a signed transaction with libbitcoinconsensus")
			.arg(args::arg("raw-tx", "the raw transaction in hex").required(true))
			.arg(args::opt("prevouts", "the outputs being spent, as comma-separated serialized \
				txouts in hex, in input order")
				.required(true))
			.arg(args::opt("input-idx", "only verify the input with this index"))
			.arg(args::opt("flags", "the script verification flags as a number; defaults to \
				all flags supported by libbitcoinconsensus"))
			.long_about(r#"
Verify the scripts of a signed transaction using libbitcoinconsensus, given
the outputs it spends.

NB The libbitcoinconsensus bindings used (v0.105) don't support taproot
verification, so transactions spending p2tr outputs fail verification.
"#)
	]
}

#[cfg(not(feature = "bitcoinconsensus"))]
fn cmd_verify<'a>() -> Vec<clap::App<'a, 'a>> {
	vec![]
}

#[cfg(feature = "bitcoinconsensus")]
fn exec_verify<'a>(args: &clap::ArgMatches<'a>) {
	use std::collections::HashMap;
	use bitcoin::consensus::validation;

	let hex_tx = args.value_of("raw-tx").need("no raw tx provided");
	let raw_tx = hex::decode(hex_tx).need("could not decode raw tx");
	let tx: Transaction = deserialize(&raw_tx).need("invalid tx format");

	let prevouts = args.value_of("prevouts").need("no prevouts provided")
		.split(",")
		.map(|h| {
			let raw = hex::decode(h).need("invalid prevout hex");
			deserialize::<TxOut>(&raw).need("invalid prevout txout format")
		})
		.collect::<Vec<_>>();
	if prevouts.len() != tx.input.len() {
		exit!("expected {} prevouts, one for each input, got {}", tx.input.len(), prevouts.len());
	}
	let flags = args.value_of("flags").map(|f| f.parse::<u32>().need("invalid flags"));

	let result = if let Some(idx) = args.value_of("input-idx") {
		let idx = idx.parse::<usize>().need("invalid input index");
		if idx >= tx.input.len() {
			exit!("input index out of range: tx has {} inputs", tx.input.len());
		}
		let prevout = &prevouts[idx];
		match flags {
			Some(flags) => validation::verify_script_with_flags(
				&prevout.script_pubkey, idx, prevout.value, &raw_tx, flags,
			),
			None => validation::verify_script(&prevout.script_pubkey, idx, prevout.value, &raw_tx),
		}.map_err(|e| format!("input {}: {}", idx, e))
	} else {
		let spent = tx.input.iter().map(|i| i.previous_output).zip(prevouts.iter().cloned())
			.collect::<HashMap<_, _>>();
		let lookup = |outpoint: &OutPoint| spent.get(outpoint).cloned();
		match flags {
			Some(flags) => tx.verify_with_flags(lookup, flags),
			None => tx.verify(lookup),
		}.map_err(|e| e.to_string())
	};

	match result {
		Ok(()) => println!("Transaction is valid."),
		Err(e) => {
			eprintln!("Transaction is invalid: {}", e);
			std::process::exit(1);
		},
	}
}
