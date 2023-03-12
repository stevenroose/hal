use std::fs::File;
use std::io::{self, BufRead, Read, Write};
use std::str::FromStr;

use base64;
use clap;
use hex;

use bitcoin::{PrivateKey, consensus::{deserialize, serialize}};
use bitcoin::util::bip32;
use bitcoin::util::psbt;
use bitcoin::{PublicKey, Transaction};
use miniscript::psbt::PsbtExt;
use secp256k1;

use crate::{cmd, util};

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("psbt", "partially signed Bitcoin transactions")
		.subcommand(cmd_create())
		.subcommand(cmd_decode())
		.subcommand(cmd_edit())
		.subcommand(cmd_finalize())
		.subcommand(cmd_merge())
		.subcommand(cmd_rawsign())
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	match matches.subcommand() {
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
		file.read_to_end(&mut buf).expect("error reading file");
		(buf, PsbtSource::File)
	} else {
		panic!("Can't load PSBT: invalid hex, base64 or unknown file");
	}
}

fn cmd_create<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("create", "create a PSBT from an unsigned raw transaction").args(&[
		cmd::arg("raw-tx", "the raw transaction in hex").required(false),
		cmd::opt("output", "where to save the merged PSBT output")
			.short("o")
			.takes_value(true)
			.required(false),
		cmd::opt("raw-stdout", "output the raw bytes of the result to stdout")
			.short("r")
			.required(false),
	])
}

fn exec_create<'a>(matches: &clap::ArgMatches<'a>) {
	let hex_tx = util::arg_or_stdin(matches, "raw-tx");
	let raw_tx = hex::decode(hex_tx.as_ref()).expect("could not decode raw tx");
	let tx: Transaction = deserialize(&raw_tx).expect("invalid tx format");

	let psbt = psbt::PartiallySignedTransaction::from_unsigned_tx(tx)
		.expect("couldn't create a PSBT from the transaction");

	let serialized = serialize(&psbt);
	if let Some(path) = matches.value_of("output") {
		let mut file = File::create(&path).expect("failed to open output file");
		file.write_all(&serialized).expect("error writing output file");
	} else if matches.is_present("raw-stdout") {
		::std::io::stdout().write_all(&serialized).unwrap();
	} else {
		print!("{}", base64::encode(&serialized));
	}
}

fn cmd_decode<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("decode", "decode a PSBT to JSON").args(&cmd::opts_networks()).args(&[
		cmd::opt_yaml(),
		cmd::arg("psbt", "the PSBT file or raw PSBT in base64/hex").required(false),
	])
}

fn exec_decode<'a>(matches: &clap::ArgMatches<'a>) {
	let input = util::arg_or_stdin(matches, "psbt");
	let (raw_psbt, _) = file_or_raw(input.as_ref());

	let psbt: psbt::PartiallySignedTransaction = deserialize(&raw_psbt).expect("invalid PSBT");

	let info = hal::GetInfo::get_info(&psbt, cmd::network(matches));
	cmd::print_output(matches, &info)
}

fn cmd_edit<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("edit", "edit a PSBT").args(&[
		cmd::arg("psbt", "PSBT to edit, either base64/hex or a file path").required(false),
		cmd::opt("input-idx", "the input index to edit")
			.display_order(1)
			.takes_value(true)
			.required(false),
		cmd::opt("output-idx", "the output index to edit")
			.display_order(2)
			.takes_value(true)
			.required(false),
		cmd::opt("output", "where to save the resulting PSBT file -- in place if omitted")
			.short("o")
			.display_order(3)
			.next_line_help(true)
			.takes_value(true)
			.required(false),
		cmd::opt("raw-stdout", "output the raw bytes of the result to stdout")
			.short("r")
			.required(false),
		//
		// values used in both inputs and outputs
		cmd::opt("redeem-script", "the redeem script")
			.display_order(99)
			.next_line_help(true)
			.takes_value(true)
			.required(false),
		cmd::opt("witness-script", "the witness script")
			.display_order(99)
			.next_line_help(true)
			.takes_value(true)
			.required(false),
		cmd::opt("hd-keypaths", "the HD wallet keypaths `<pubkey>:<master-fp>:<path>,...`")
			.display_order(99)
			.next_line_help(true)
			.takes_value(true)
			.required(false),
		cmd::opt("hd-keypaths-add", "add an HD wallet keypath `<pubkey>:<master-fp>:<path>`")
			.display_order(99)
			.next_line_help(true)
			.takes_value(true)
			.required(false),
		//
		// input values
		cmd::opt("non-witness-utxo", "the non-witness UTXO field in hex (full transaction)")
			.display_order(99)
			.next_line_help(true)
			.takes_value(true)
			.required(false),
		cmd::opt("witness-utxo", "the witness UTXO field in hex (only output)")
			.display_order(99)
			.next_line_help(true)
			.takes_value(true)
			.required(false),
		cmd::opt("partial-sigs", "set partial sigs `<pubkey>:<signature>,...`")
			.display_order(99)
			.next_line_help(true)
			.takes_value(true)
			.required(false),
		cmd::opt("partial-sigs-add", "add a partial sig pair `<pubkey>:<signature>`")
			.display_order(99)
			.next_line_help(true)
			.takes_value(true)
			.required(false),
		cmd::opt("sighash-type", "the sighash type")
			.display_order(99)
			.next_line_help(true)
			.takes_value(true)
			.required(false),
		// (omitted) redeem-script
		// (omitted) witness-script
		// (omitted) hd-keypaths
		// (omitted) hd-keypaths-add
		cmd::opt("final-script-sig", "set final script signature")
			.display_order(99)
			.next_line_help(true)
			.takes_value(true)
			.required(false),
		cmd::opt("final-script-witness", "set final script witness as comma-separated hex values")
			.display_order(99)
			.next_line_help(true)
			.takes_value(true)
			.required(false),
		//
		// output values
		// (omitted) redeem-script
		// (omitted) witness-script
		// (omitted) hd-keypaths
		// (omitted) hd-keypaths-add
	])
}

/// Parses a `<pubkey>:<signature>` pair.
fn parse_partial_sig_pair(pair_str: &str) -> (PublicKey, bitcoin::EcdsaSig) {
	let mut pair = pair_str.splitn(2, ":");
	let pubkey = pair.next().unwrap().parse().expect("invalid partial sig pubkey");
	let sig = {
		let hex = pair.next().expect("invalid partial sig pair: missing signature");
		hex::decode(&hex).expect("invalid partial sig signature hex")
	};
	(pubkey, bitcoin::EcdsaSig::from_slice(&sig).expect("partial sig is not valid ecdsa"))
}

fn parse_hd_keypath_triplet(
	triplet_str: &str,
) -> (bitcoin::secp256k1::PublicKey, (bip32::Fingerprint, bip32::DerivationPath)) {
	let mut triplet = triplet_str.splitn(3, ":");
	let pubkey = triplet.next().unwrap().parse().expect("invalid HD keypath pubkey");
	let fp = {
		let hex = triplet.next().expect("invalid HD keypath triplet: missing fingerprint");
		let raw = hex::decode(&hex).expect("invalid HD keypath fingerprint hex");
		if raw.len() != 4 {
			panic!("invalid HD keypath fingerprint size: {} instead of 4", raw.len());
		}
		raw[..].into()
	};
	let path = triplet
		.next()
		.expect("invalid HD keypath triplet: missing HD path")
		.parse()
		.expect("invalid derivation path format");
	(pubkey, (fp, path))
}

fn edit_input<'a>(
	idx: usize,
	matches: &clap::ArgMatches<'a>,
	psbt: &mut psbt::PartiallySignedTransaction,
) {
	let input = psbt.inputs.get_mut(idx).expect("input index out of range");

	if let Some(hex) = matches.value_of("non-witness-utxo") {
		let raw = hex::decode(&hex).expect("invalid non-witness-utxo hex");
		let utxo = deserialize(&raw).expect("invalid non-witness-utxo transaction");
		input.non_witness_utxo = Some(utxo);
	}

	if let Some(hex) = matches.value_of("witness-utxo") {
		let raw = hex::decode(&hex).expect("invalid witness-utxo hex");
		let utxo = deserialize(&raw).expect("invalid witness-utxo transaction");
		input.witness_utxo = Some(utxo);
	}

	if let Some(csv) = matches.value_of("partial-sigs") {
		input.partial_sigs = csv.split(",").map(parse_partial_sig_pair).collect();
	}
	if let Some(pairs) = matches.values_of("partial-sigs-add") {
		for (pk, sig) in pairs.map(parse_partial_sig_pair) {
			if input.partial_sigs.insert(pk, sig).is_some() {
				panic!("public key {} is already in partial sigs", &pk);
			}
		}
	}

	if let Some(sht) = matches.value_of("sighash-type") {
		input.sighash_type = Some(hal::psbt::ecdsa_sighashtype_from_string(&sht));
	}

	if let Some(hex) = matches.value_of("redeem-script") {
		let raw = hex::decode(&hex).expect("invalid redeem-script hex");
		input.redeem_script = Some(raw.into());
	}

	if let Some(hex) = matches.value_of("witness-script") {
		let raw = hex::decode(&hex).expect("invalid witness-script hex");
		input.witness_script = Some(raw.into());
	}

	if let Some(csv) = matches.value_of("hd-keypaths") {
		input.bip32_derivation = csv.split(",").map(parse_hd_keypath_triplet).collect();
	}
	if let Some(triplets) = matches.values_of("hd-keypaths-add") {
		for (pk, pair) in triplets.map(parse_hd_keypath_triplet) {
			if input.bip32_derivation.insert(pk, pair).is_some() {
				panic!("public key {} is already in HD keypaths", &pk);
			}
		}
	}

	if let Some(hex) = matches.value_of("final-script-sig") {
		let raw = hex::decode(&hex).expect("invalid final-script-sig hex");
		input.final_script_sig = Some(raw.into());
	}

	if let Some(csv) = matches.value_of("final-script-witness") {
		let vhex = csv.split(",");
		let vraw = vhex.map(|h| hex::decode(&h).expect("invalid final-script-witness hex"));
		input.final_script_witness = Some(bitcoin::Witness::from_vec(vraw.collect()));
	}
}

fn edit_output<'a>(
	idx: usize,
	matches: &clap::ArgMatches<'a>,
	psbt: &mut psbt::PartiallySignedTransaction,
) {
	let output = psbt.outputs.get_mut(idx).expect("output index out of range");

	if let Some(hex) = matches.value_of("redeem-script") {
		let raw = hex::decode(&hex).expect("invalid redeem-script hex");
		output.redeem_script = Some(raw.into());
	}

	if let Some(hex) = matches.value_of("witness-script") {
		let raw = hex::decode(&hex).expect("invalid witness-script hex");
		output.witness_script = Some(raw.into());
	}

	if let Some(csv) = matches.value_of("hd-keypaths") {
		output.bip32_derivation = csv.split(",").map(parse_hd_keypath_triplet).collect();
	}
	if let Some(triplets) = matches.values_of("hd-keypaths-add") {
		for (pk, pair) in triplets.map(parse_hd_keypath_triplet) {
			if output.bip32_derivation.insert(pk, pair).is_some() {
				panic!("public key {} is already in HD keypaths", &pk);
			}
		}
	}
}

fn exec_edit<'a>(matches: &clap::ArgMatches<'a>) {
	let input = util::arg_or_stdin(matches, "psbt");
	let (raw, source) = file_or_raw(input.as_ref());
	let mut psbt: psbt::PartiallySignedTransaction =
		deserialize(&raw).expect("invalid PSBT format");

	match (matches.value_of("input-idx"), matches.value_of("output-idx")) {
		(None, None) => panic!("no input or output index provided"),
		(Some(_), Some(_)) => panic!("can only edit an input or an output at a time"),
		(Some(idx), _) => {
			edit_input(idx.parse().expect("invalid input index"), &matches, &mut psbt)
		}
		(_, Some(idx)) => {
			edit_output(idx.parse().expect("invalid output index"), &matches, &mut psbt)
		}
	}

	let edited_raw = serialize(&psbt);
	if let Some(path) = matches.value_of("output") {
		let mut file = File::create(&path).expect("failed to open output file");
		file.write_all(&edited_raw).expect("error writing output file");
	} else if matches.is_present("raw-stdout") {
		::std::io::stdout().write_all(&edited_raw).unwrap();
	} else {
		match source {
			PsbtSource::Hex => print!("{}", hex::encode(&edited_raw)),
			PsbtSource::Base64 => print!("{}", base64::encode(&edited_raw)),
			PsbtSource::File => {
				let path = matches.value_of("psbt").unwrap();
				let mut file = File::create(&path).expect("failed to PSBT file for writing");
				file.write_all(&edited_raw).expect("error writing PSBT file");
			}
		}
	}
}

fn cmd_finalize<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("finalize", "finalize a PSBT and print the fully signed tx in hex").args(&[
		cmd::arg("psbt", "PSBT to finalize, either base64/hex or a file path").required(false),
		cmd::opt("raw-stdout", "output the raw bytes of the result to stdout")
			.short("r")
			.required(false),
	])
}

fn exec_finalize<'a>(matches: &clap::ArgMatches<'a>) {
	let input = util::arg_or_stdin(matches, "psbt");
	let (raw, _) = file_or_raw(input.as_ref());
	let psbt: psbt::PartiallySignedTransaction = deserialize(&raw).expect("invalid PSBT format");

	// Create a secp context, should there be one with static lifetime?
	let secp = &secp256k1::Secp256k1::verification_only();
	let psbt = psbt.finalize(secp).expect("failed to finalize");

	let finalized_raw = serialize(&psbt.extract_tx());
	if matches.is_present("raw-stdout") {
		::std::io::stdout().write_all(&finalized_raw).unwrap();
	} else {
		print!("{}", ::hex::encode(&finalized_raw));
	}
}

fn cmd_merge<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("merge", "merge multiple PSBT files into one").args(&[
		cmd::arg("psbts", "PSBTs to merge; can be file paths or base64/hex")
			.multiple(true)
			.required(true),
		cmd::opt("output", "where to save the merged PSBT output")
			.short("o")
			.takes_value(true)
			.required(false),
		cmd::opt("raw-stdout", "output the raw bytes of the result to stdout")
			.short("r")
			.required(false),
	])
}

fn exec_merge<'a>(matches: &clap::ArgMatches<'a>) {
	let stdin = io::stdin();
	let mut parts: Box<dyn Iterator<Item = psbt::PartiallySignedTransaction>> =
		if let Some(values) = matches.values_of("psbts")
	{
		Box::new(values.into_iter().map(|f| {
			let (raw, _) = file_or_raw(&f);
			let psbt: psbt::PartiallySignedTransaction =
				deserialize(&raw).expect("invalid PSBT format");
			psbt
		}))
	} else {
		// Read from stdin.
		let stdin_lock = stdin.lock();
		let buf = io::BufReader::new(stdin_lock);
		Box::new(buf.lines().take_while(|l| l.is_ok() && !l.as_ref().unwrap().is_empty()).map(|l| {
			let (raw, _) = file_or_raw(&l.unwrap());
			deserialize::<psbt::PartiallySignedTransaction>(&raw)
				.expect("invalid PSBT format")
		}))
	};

	let mut merged = parts.next().unwrap();
	for (idx, part) in parts.enumerate() {
		if part.unsigned_tx != merged.unsigned_tx {
			panic!("PSBTs are not compatible");
		}

		merged.combine(part).expect(&format!("error merging PSBT #{}", idx));
	}

	let merged_raw = serialize(&merged);
	if let Some(path) = matches.value_of("output") {
		let mut file = File::create(&path).expect("failed to open output file");
		file.write_all(&merged_raw).expect("error writing output file");
	} else if matches.is_present("raw-stdout") {
		::std::io::stdout().write_all(&merged_raw).unwrap();
	} else {
		print!("{}", base64::encode(&merged_raw));
	}
}

fn cmd_rawsign<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("rawsign", "sign a psbt with private key and add sig to partial sigs").args(&[
		cmd::arg("psbt", "PSBT to finalize, either base64/hex or a file path").required(false),
		cmd::arg("input-idx", "the input index to edit").required(true),
		cmd::arg("priv-key", "the private key in WIF/hex").required(true),
		cmd::arg("compressed", "Whether the corresponding pk is compressed")
			.required(false)
			.default_value("true"),
		cmd::opt("raw-stdout", "output the raw bytes of the result to stdout")
			.short("r")
			.required(false),
		cmd::opt("output", "where to save the resulting PSBT file -- in place if omitted")
			.short("o")
			.takes_value(true)
			.required(false),
	])
}

fn exec_rawsign<'a>(matches: &clap::ArgMatches<'a>) {
	let input = util::arg_or_stdin(matches, "psbt");
	let (raw, source) = file_or_raw(input.as_ref());
	let mut psbt: psbt::PartiallySignedTransaction = deserialize(&raw).expect("invalid PSBT format");

	let priv_key = matches.value_of("priv-key").expect("no key provided");
	let i = matches.value_of("input-idx").expect("Input index not provided")
		.parse::<usize>().expect("input-idx must be a positive integer");
	let compressed = matches.value_of("compressed").unwrap()
		.parse::<bool>().expect("Compressed must be boolean");

	if i >= psbt.inputs.len() {
		panic!("PSBT input index out of range")
	}

	let tx =  psbt.clone().extract_tx();
	let mut cache = bitcoin::util::sighash::SighashCache::new(&tx);

	let sk = if let Ok(privkey) = PrivateKey::from_str(&priv_key) {
		privkey.inner
	} else if let Ok(sk) = secp256k1::SecretKey::from_str(&priv_key) {
		sk
	} else {
		panic!("invalid WIF/hex private key: {}", priv_key);
	};
	let secp = secp256k1::Secp256k1::signing_only();
	let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
	let pk = bitcoin::PublicKey {
		compressed: compressed,
		inner: pk,
	};
	let msg = psbt.sighash_msg(i, &mut cache, None)
		.expect("error computing sighash message on psbt");
	let secp_sig = match msg {
		miniscript::psbt::PsbtSighashMsg::EcdsaSighash(sighash) => {
			let msg = secp256k1::Message::from_slice(&sighash)
				.expect("error computing sighash message on psbt");
			secp.sign_ecdsa(&msg, &sk)
		},
		miniscript::psbt::PsbtSighashMsg::TapSighash(_) => {
			panic!("Signing taproot transactions is not yet suppported")
		},
	};

	let sighashtype = psbt.inputs[i].sighash_type
		.expect("error locating sighash type on the selected input")
		.ecdsa_hash_ty()
		.expect("schnorr signatures are not yet supported");
	let mut btc_sig = secp_sig.serialize_der().as_ref().to_vec();
	btc_sig.push(sighashtype.to_u32() as u8);

	// mutate the psbt
	psbt.inputs[i].partial_sigs.insert(pk, bitcoin::EcdsaSig::from_slice(&btc_sig)
		.expect("failed to sign psbt"));
	let raw = serialize(&psbt);
	if let Some(path) = matches.value_of("output") {
		let mut file = File::create(&path).expect("failed to open output file");
		file.write_all(&raw).expect("error writing output file");
	} else if matches.is_present("raw-stdout") {
		::std::io::stdout().write_all(&raw).unwrap();
	} else {
		match source {
			PsbtSource::Hex => println!("{}", hex::encode(&raw)),
			PsbtSource::Base64 => println!("{}", base64::encode(&raw)),
			PsbtSource::File => {
				let path = matches.value_of("psbt").unwrap();
				let mut file = File::create(&path).expect("failed to PSBT file for writing");
				file.write_all(&raw).expect("error writing PSBT file");
			}
		}
	}
}
