use std::fs::File;
use std::io::{self, BufRead, Read, Write};
use std::str::FromStr;

use base64;
use clap;
use hex;

use bitcoin::{bip32, ecdsa, EcdsaSighashType, Psbt, PublicKey, Transaction};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use miniscript::psbt::PsbtExt;
use secp256k1;

use crate::prelude::*;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("psbt", "partially signed Bitcoin transactions")
		.subcommand(cmd_create())
		.subcommand(cmd_decode())
		.subcommand(cmd_edit())
		.subcommand(cmd_finalize())
		.subcommand(cmd_merge())
		.subcommand(cmd_rawsign())
}

pub fn execute<'a>(args: &clap::ArgMatches<'a>) {
	match args.subcommand() {
		("create", Some(ref m)) => exec_create(&m),
		("decode", Some(ref m)) => exec_decode(&m),
		("edit", Some(ref m)) => exec_edit(&m),
		("finalize", Some(ref m)) => exec_finalize(&m),
		("merge", Some(ref m)) => exec_merge(&m),
		("rawsign", Some(ref m)) => exec_rawsign(&m),
		(c, _) => eprintln!("command {} unknown", c),
	};
}

#[derive(Debug)]
enum PsbtSource {
	Base64,
	Hex,
	File,
}

/// Tries to decode the string as hex and base64, if it works, returns the bytes.
/// If not, tries to open a filename with the given string as relative path, if it works, returns
/// the content bytes.
/// Also returns an enum value indicating which source worked.
fn file_or_raw(flag: &str) -> (Vec<u8>, PsbtSource) {
	if let Ok(raw) = hex::decode(&flag) {
		(raw, PsbtSource::Hex)
	} else if let Ok(raw) = base64::decode(&flag) {
		(raw, PsbtSource::Base64)
	} else if let Ok(mut file) = File::open(&flag) {
		let mut buf = Vec::new();
		file.read_to_end(&mut buf).need("error reading file");
		(buf, PsbtSource::File)
	} else {
		exit!("Can't load PSBT: invalid hex, base64 or unknown file");
	}
}

fn cmd_create<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("create", "create a PSBT from an unsigned raw transaction").args(&[
		args::arg("raw-tx", "the raw transaction in hex").required(false),
		args::opt("output", "where to save the merged PSBT output")
			.short("o"),
		args::flag("raw-stdout", "output the raw bytes of the result to stdout")
			.short("r"),
	])
}

fn exec_create<'a>(args: &clap::ArgMatches<'a>) {
	let hex_tx = util::arg_or_stdin(args, "raw-tx");
	let raw_tx = hex::decode(hex_tx.as_ref()).need("could not decode raw tx");
	let tx = deserialize::<Transaction>(&raw_tx).need("invalid tx format");

	let psbt = Psbt::from_unsigned_tx(tx).need("couldn't create a PSBT from the transaction");

	let serialized = psbt.serialize();
	if let Some(path) = args.value_of("output") {
		let mut file = File::create(&path).need("failed to open output file");
		file.write_all(&serialized).need("error writing output file");
	} else if args.is_present("raw-stdout") {
		::std::io::stdout().write_all(&serialized).unwrap();
	} else {
		print!("{}", base64::encode(&serialized));
	}
}

fn cmd_decode<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("decode", "decode a PSBT to JSON")
		.arg(args::arg("psbt", "the PSBT file or raw PSBT in base64/hex").required(false))
}

fn exec_decode<'a>(args: &clap::ArgMatches<'a>) {
	let input = util::arg_or_stdin(args, "psbt");
	let (raw_psbt, _) = file_or_raw(input.as_ref());

	let psbt = Psbt::deserialize(&raw_psbt).need("invalid PSBT");

	let info = hal::GetInfo::get_info(&psbt, args.network());
	args.print_output(&info)
}

fn cmd_edit<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("edit", "edit a PSBT").args(&[
		args::arg("psbt", "PSBT to edit, either base64/hex or a file path").required(false),
		args::opt("input-idx", "the input index to edit")
			.display_order(1),
		args::opt("output-idx", "the output index to edit")
			.display_order(2),
		args::opt("output", "where to save the resulting PSBT file -- in place if omitted")
			.short("o")
			.display_order(3)
			.next_line_help(true),
		args::flag("raw-stdout", "output the raw bytes of the result to stdout")
			.short("r"),
		//
		// values used in both inputs and outputs
		args::opt("redeem-script", "the redeem script")
			.display_order(99)
			.next_line_help(true),
		args::opt("witness-script", "the witness script")
			.display_order(99)
			.next_line_help(true),
		args::opt("hd-keypaths", "the HD wallet keypaths `<pubkey>:<master-fp>:<path>,...`")
			.display_order(99)
			.next_line_help(true),
		args::opt("hd-keypaths-add", "add an HD wallet keypath `<pubkey>:<master-fp>:<path>`")
			.display_order(99)
			.next_line_help(true),
		//
		// input values
		args::opt("non-witness-utxo", "the non-witness UTXO field in hex (full transaction)")
			.display_order(99)
			.next_line_help(true),
		args::opt("witness-utxo", "the witness UTXO field in hex (only output)")
			.display_order(99)
			.next_line_help(true),
		args::opt("partial-sigs", "set partial sigs `<pubkey>:<signature>,...`")
			.display_order(99)
			.next_line_help(true),
		args::opt("partial-sigs-add", "add a partial sig pair `<pubkey>:<signature>`")
			.display_order(99)
			.next_line_help(true),
		args::opt("sighash-type", "the sighash type")
			.display_order(99)
			.next_line_help(true),
		// (omitted) redeem-script
		// (omitted) witness-script
		// (omitted) hd-keypaths
		// (omitted) hd-keypaths-add
		args::opt("final-script-sig", "set final script signature")
			.display_order(99)
			.next_line_help(true),
		args::opt("final-script-witness", "set final script witness as comma-separated hex values")
			.display_order(99)
			.next_line_help(true),
		//
		// output values
		// (omitted) redeem-script
		// (omitted) witness-script
		// (omitted) hd-keypaths
		// (omitted) hd-keypaths-add
	])
}

/// Parses a `<pubkey>:<signature>` pair.
fn parse_partial_sig_pair(pair_str: &str) -> (PublicKey, ecdsa::Signature) {
	let mut pair = pair_str.splitn(2, ":");
	let pubkey = pair.next().unwrap().parse().need("invalid partial sig pubkey");
	let sig = {
		let hex = pair.next().need("invalid partial sig pair: missing signature");
		hex::decode(&hex).need("invalid partial sig signature hex")
	};
	(pubkey, ecdsa::Signature::from_slice(&sig).need("partial sig is not valid ecdsa"))
}

fn parse_hd_keypath_triplet(
	triplet_str: &str,
) -> (bitcoin::secp256k1::PublicKey, (bip32::Fingerprint, bip32::DerivationPath)) {
	let mut triplet = triplet_str.splitn(3, ":");
	let pubkey = triplet.next().unwrap().parse().need("invalid HD keypath pubkey");
	let fp = {
		let hex = triplet.next().need("invalid HD keypath triplet: missing fingerprint");
		bip32::Fingerprint::from_str(&hex).need("invalid HD keypath fingerprint hex")
	};
	let path = triplet
		.next()
		.need("invalid HD keypath triplet: missing HD path")
		.parse()
		.need("invalid derivation path format");
	(pubkey, (fp, path))
}

fn edit_input<'a>(
	idx: usize,
	args: &clap::ArgMatches<'a>,
	psbt: &mut Psbt,
) {
	let input = psbt.inputs.get_mut(idx).need("input index out of range");

	if let Some(hex) = args.value_of("non-witness-utxo") {
		let raw = hex::decode(&hex).need("invalid non-witness-utxo hex");
		let utxo = deserialize(&raw).need("invalid non-witness-utxo transaction");
		input.non_witness_utxo = Some(utxo);
	}

	if let Some(hex) = args.value_of("witness-utxo") {
		let raw = hex::decode(&hex).need("invalid witness-utxo hex");
		let utxo = deserialize(&raw).need("invalid witness-utxo transaction");
		input.witness_utxo = Some(utxo);
	}

	if let Some(csv) = args.value_of("partial-sigs") {
		input.partial_sigs = csv.split(",").map(parse_partial_sig_pair).collect();
	}
	if let Some(pairs) = args.values_of("partial-sigs-add") {
		for (pk, sig) in pairs.map(parse_partial_sig_pair) {
			if input.partial_sigs.insert(pk, sig).is_some() {
				exit!("public key {} is already in partial sigs", &pk);
			}
		}
	}

	if let Some(sht) = args.value_of("sighash-type") {
		input.sighash_type = Some(hal::psbt::ecdsa_sighashtype_from_string(&sht).need("invalid sighash string"));
	}

	if let Some(hex) = args.value_of("redeem-script") {
		let raw = hex::decode(&hex).need("invalid redeem-script hex");
		input.redeem_script = Some(raw.into());
	}

	if let Some(hex) = args.value_of("witness-script") {
		let raw = hex::decode(&hex).need("invalid witness-script hex");
		input.witness_script = Some(raw.into());
	}

	if let Some(csv) = args.value_of("hd-keypaths") {
		input.bip32_derivation = csv.split(",").map(parse_hd_keypath_triplet).collect();
	}
	if let Some(triplets) = args.values_of("hd-keypaths-add") {
		for (pk, pair) in triplets.map(parse_hd_keypath_triplet) {
			if input.bip32_derivation.insert(pk, pair).is_some() {
				exit!("public key {} is already in HD keypaths", &pk);
			}
		}
	}

	if let Some(hex) = args.value_of("final-script-sig") {
		let raw = hex::decode(&hex).need("invalid final-script-sig hex");
		input.final_script_sig = Some(raw.into());
	}

	if let Some(csv) = args.value_of("final-script-witness") {
		let vhex = csv.split(",");
		let vraw = vhex.map(|h| hex::decode(&h).need("invalid final-script-witness hex"));
		input.final_script_witness = Some(bitcoin::Witness::from_slice(&vraw.collect::<Vec<_>>()));
	}
}

fn edit_output<'a>(idx: usize, args: &clap::ArgMatches<'a>, psbt: &mut Psbt) {
	let output = psbt.outputs.get_mut(idx).need("output index out of range");

	if let Some(hex) = args.value_of("redeem-script") {
		let raw = hex::decode(&hex).need("invalid redeem-script hex");
		output.redeem_script = Some(raw.into());
	}

	if let Some(hex) = args.value_of("witness-script") {
		let raw = hex::decode(&hex).need("invalid witness-script hex");
		output.witness_script = Some(raw.into());
	}

	if let Some(csv) = args.value_of("hd-keypaths") {
		output.bip32_derivation = csv.split(",").map(parse_hd_keypath_triplet).collect();
	}
	if let Some(triplets) = args.values_of("hd-keypaths-add") {
		for (pk, pair) in triplets.map(parse_hd_keypath_triplet) {
			if output.bip32_derivation.insert(pk, pair).is_some() {
				exit!("public key {} is already in HD keypaths", &pk);
			}
		}
	}
}

fn exec_edit<'a>(args: &clap::ArgMatches<'a>) {
	let input = util::arg_or_stdin(args, "psbt");
	let (raw, source) = file_or_raw(input.as_ref());
	let mut psbt = Psbt::deserialize(&raw).need("invalid PSBT format");

	match (args.value_of("input-idx"), args.value_of("output-idx")) {
		(None, None) => exit!("no input or output index provided"),
		(Some(_), Some(_)) => exit!("can only edit an input or an output at a time"),
		(Some(idx), _) => {
			edit_input(idx.parse().need("invalid input index"), &args, &mut psbt)
		}
		(_, Some(idx)) => {
			edit_output(idx.parse().need("invalid output index"), &args, &mut psbt)
		}
	}

	let edited_raw = psbt.serialize();
	if let Some(path) = args.value_of("output") {
		let mut file = File::create(&path).need("failed to open output file");
		file.write_all(&edited_raw).need("error writing output file");
	} else if args.is_present("raw-stdout") {
		::std::io::stdout().write_all(&edited_raw).unwrap();
	} else {
		match source {
			PsbtSource::Hex => print!("{}", hex::encode(&edited_raw)),
			PsbtSource::Base64 => print!("{}", base64::encode(&edited_raw)),
			PsbtSource::File => {
				let path = args.value_of("psbt").unwrap();
				let mut file = File::create(&path).need("failed to PSBT file for writing");
				file.write_all(&edited_raw).need("error writing PSBT file");
			}
		}
	}
}

fn cmd_finalize<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("finalize", "finalize a PSBT and print the fully signed tx in hex").args(&[
		args::arg("psbt", "PSBT to finalize, either base64/hex or a file path").required(false),
		args::flag("raw-stdout", "output the raw bytes of the result to stdout")
			.short("r"),
	])
}

fn exec_finalize<'a>(args: &clap::ArgMatches<'a>) {
	let input = util::arg_or_stdin(args, "psbt");
	let (raw, _) = file_or_raw(input.as_ref());
	let psbt = Psbt::deserialize(&raw).need("invalid PSBT format");

	// Create a secp context, should there be one with static lifetime?
	let psbt = psbt.finalize(&SECP).unwrap_or_else(|(_, errs)| {
		let errs = errs.into_iter().map(|e| e.to_string()).collect::<Vec<_>>();
		exit!("failed to finalize psbt: {}", errs.join(", "));
	});

	let finalized_raw = serialize(&psbt.extract_tx().need("failed to extract tx from psbt"));
	if args.is_present("raw-stdout") {
		::std::io::stdout().write_all(&finalized_raw).unwrap();
	} else {
		print!("{}", ::hex::encode(&finalized_raw));
	}
}

fn cmd_merge<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("merge", "merge multiple PSBT files into one").args(&[
		args::arg("psbts", "PSBTs to merge; can be file paths or base64/hex")
			.multiple(true)
			.required(true),
		args::opt("output", "where to save the merged PSBT output")
			.short("o"),
		args::flag("raw-stdout", "output the raw bytes of the result to stdout")
			.short("r"),
	])
}

fn exec_merge<'a>(args: &clap::ArgMatches<'a>) {
	let stdin = io::stdin();
	let mut parts: Box<dyn Iterator<Item = Psbt>> = if let Some(values) = args.values_of("psbts") {
		Box::new(values.into_iter().map(|f| {
			let (raw, _) = file_or_raw(&f);
			Psbt::deserialize(&raw).need("invalid PSBT format")
		}))
	} else {
		// Read from stdin.
		let stdin_lock = stdin.lock();
		let buf = io::BufReader::new(stdin_lock);
		Box::new(buf.lines().take_while(|l| l.is_ok() && !l.as_ref().unwrap().is_empty()).map(|l| {
			let (raw, _) = file_or_raw(&l.unwrap());
			Psbt::deserialize(&raw).need("invalid PSBT format")
		}))
	};

	let mut merged = parts.next().unwrap();
	for (idx, part) in parts.enumerate() {
		if part.unsigned_tx != merged.unsigned_tx {
			panic!("PSBTs are not compatible");
		}

		merged.combine(part).need(&format!("error merging PSBT #{}", idx));
	}

	let merged_raw = merged.serialize();
	if let Some(path) = args.value_of("output") {
		let mut file = File::create(&path).need("failed to open output file");
		file.write_all(&merged_raw).need("error writing output file");
	} else if args.is_present("raw-stdout") {
		::std::io::stdout().write_all(&merged_raw).unwrap();
	} else {
		print!("{}", base64::encode(&merged_raw));
	}
}

fn cmd_rawsign<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("rawsign", "sign a psbt with private key and add sig to partial sigs").args(&[
		args::arg("psbt", "PSBT to finalize, either base64/hex or a file path").required(false),
		args::arg("input-idx", "the input index to edit").required(true),
		args::arg("priv-key", "the private key in WIF/hex").required(true),
		args::flag("compressed", "Whether the corresponding pk is compressed")
			.required(false)
			.default_value("true"),
		args::flag("raw-stdout", "output the raw bytes of the result to stdout")
			.short("r"),
		args::opt("output", "where to save the resulting PSBT file -- in place if omitted")
			.short("o"),
	])
}

fn exec_rawsign<'a>(args: &clap::ArgMatches<'a>) {
	let input = util::arg_or_stdin(args, "psbt");
	let (raw, source) = file_or_raw(input.as_ref());
	let mut psbt = Psbt::deserialize(&raw).need("invalid PSBT format");

	let sk = args.need_privkey("priv-key").inner;
	let i = args.value_of("input-idx").need("Input index not provided")
		.parse::<usize>().need("input-idx must be a positive integer");
	let compressed = args.value_of("compressed").unwrap()
		.parse::<bool>().need("Compressed must be boolean");

	if i >= psbt.inputs.len() {
		panic!("PSBT input index out of range")
	}

	let tx =  psbt.clone().extract_tx().need("failed to extract tx from psbt");
	let mut cache = bitcoin::sighash::SighashCache::new(&tx);

	let pk = secp256k1::PublicKey::from_secret_key(&SECP, &sk);
	let pk = bitcoin::PublicKey { compressed, inner: pk };
	let msg = psbt.sighash_msg(i, &mut cache, None)
		.need("error computing sighash message on psbt");
	let secp_sig = match msg {
		miniscript::psbt::PsbtSighashMsg::LegacySighash(sighash) => {
			let msg = secp256k1::Message::from_digest(sighash.to_byte_array());
			SECP.sign_ecdsa(&msg, &sk)
		},
		miniscript::psbt::PsbtSighashMsg::SegwitV0Sighash(sighash) => {
			let msg = secp256k1::Message::from_digest(sighash.to_byte_array());
			SECP.sign_ecdsa(&msg, &sk)
		},
		miniscript::psbt::PsbtSighashMsg::TapSighash(_) => {
			//TODO(stevenroose) 
			panic!("Signing taproot transactions is not yet suppported")
		},
	};

	let sighashtype = psbt.inputs[i].sighash_type
		.map(|t| t.ecdsa_hash_ty().need("schnorr signatures are not yet supported"))
		.unwrap_or_else(|| {
			eprintln!("No sighash type set for input {}, so signing with SIGHASH_ALL", i+1);
			EcdsaSighashType::All
		});
	let sig = ecdsa::Signature {
		signature: secp_sig,
		sighash_type: sighashtype,
	};

	// mutate the psbt
	psbt.inputs[i].partial_sigs.insert(pk, sig);
	let raw = psbt.serialize();
	if let Some(path) = args.value_of("output") {
		let mut file = File::create(&path).need("failed to open output file");
		file.write_all(&raw).need("error writing output file");
	} else if args.is_present("raw-stdout") {
		::std::io::stdout().write_all(&raw).unwrap();
	} else {
		match source {
			PsbtSource::Hex => println!("{}", hex::encode(&raw)),
			PsbtSource::Base64 => println!("{}", base64::encode(&raw)),
			PsbtSource::File => {
				let path = args.value_of("psbt").unwrap();
				let mut file = File::create(&path).need("failed to PSBT file for writing");
				file.write_all(&raw).need("error writing PSBT file");
			}
		}
	}
}
