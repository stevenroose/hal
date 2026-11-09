use std::fs::File;
use std::io::{self, BufRead, Read, Write};
use std::str::FromStr;

use base64;
use clap;
use hex;

use bitcoin::{absolute, bip32, ecdsa, EcdsaSighashType, Psbt, PublicKey, Transaction};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use miniscript::psbt::PsbtExt;
use psbt_v2::v2 as psbtv2;
use secp256k1;

use hal::psbt::{psbt_v0_to_v2, psbt_v2_to_v0};
use crate::prelude::*;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("psbt", "partially signed Bitcoin transactions")
		.subcommand(cmd_create())
		.subcommand(cmd_decode())
		.subcommand(cmd_edit())
		.subcommand(cmd_finalize())
		.subcommand(cmd_merge())
		.subcommand(cmd_rawsign())
		.subcommand(cmd_convert())
}

pub fn execute<'a>(args: &clap::ArgMatches<'a>) {
	match args.subcommand() {
		("create", Some(ref m)) => exec_create(&m),
		("decode", Some(ref m)) => exec_decode(&m),
		("edit", Some(ref m)) => exec_edit(&m),
		("finalize", Some(ref m)) => exec_finalize(&m),
		("merge", Some(ref m)) => exec_merge(&m),
		("rawsign", Some(ref m)) => exec_rawsign(&m),
		("convert", Some(ref m)) => exec_convert(&m),
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

/// A PSBT of either version 0 (BIP-174) or version 2 (BIP-370).
enum AnyPsbt {
	V0(Psbt),
	V2(psbtv2::Psbt),
}

impl AnyPsbt {
	/// Deserialize a PSBT of any version, exiting on failure.
	fn deserialize(raw: &[u8]) -> AnyPsbt {
		match Psbt::deserialize(raw) {
			Ok(psbt) => AnyPsbt::V0(psbt),
			Err(e0) => match psbtv2::Psbt::deserialize(raw) {
				Ok(psbt) => AnyPsbt::V2(psbt),
				// NB the Display impl of the psbt-v2 error is not implemented
				// yet in v0.3.0, so we use Debug.
				Err(e2) => exit!("invalid PSBT: as PSBTv0: {}; as PSBTv2: {:?}", e0, e2),
			},
		}
	}

	fn serialize(&self) -> Vec<u8> {
		match self {
			AnyPsbt::V0(psbt) => psbt.serialize(),
			AnyPsbt::V2(psbt) => psbt.serialize(),
		}
	}

	fn version(&self) -> u32 {
		match self {
			AnyPsbt::V0(_) => 0,
			AnyPsbt::V2(_) => 2,
		}
	}

	/// Get a PSBTv0 version of this PSBT, converting if needed.
	fn to_v0(&self) -> Psbt {
		match self {
			AnyPsbt::V0(psbt) => psbt.clone(),
			AnyPsbt::V2(psbt) => psbt_v2_to_v0(psbt.clone())
				.need("can't convert PSBTv2 to PSBTv0"),
		}
	}

	fn into_v0(self) -> Psbt {
		match self {
			AnyPsbt::V0(psbt) => psbt,
			AnyPsbt::V2(psbt) => psbt_v2_to_v0(psbt).need("can't convert PSBTv2 to PSBTv0"),
		}
	}

	fn into_v2(self) -> psbtv2::Psbt {
		match self {
			AnyPsbt::V0(psbt) => psbt_v0_to_v2(psbt),
			AnyPsbt::V2(psbt) => psbt,
		}
	}
}

/// Write the serialized PSBT to the requested destination.
///
/// Uses the --output file if given, raw bytes to stdout if --raw-stdout is
/// given, otherwise the same encoding as the source: hex or base64 to stdout
/// or the file in place. When no source is given, base64 is used.
fn write_psbt<'a>(args: &clap::ArgMatches<'a>, raw: &[u8], source: Option<PsbtSource>) {
	if let Some(path) = args.value_of("output") {
		let mut file = File::create(&path).need("failed to open output file");
		file.write_all(raw).need("error writing output file");
	} else if args.is_present("raw-stdout") {
		::std::io::stdout().write_all(raw).unwrap();
	} else {
		match source {
			Some(PsbtSource::Hex) => print!("{}", hex::encode(raw)),
			Some(PsbtSource::Base64) | None => print!("{}", base64::encode(raw)),
			Some(PsbtSource::File) => {
				let path = args.value_of("psbt").unwrap();
				let mut file = File::create(&path).need("failed to PSBT file for writing");
				file.write_all(raw).need("error writing PSBT file");
			}
		}
	}
}

fn cmd_create<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("create", "create a PSBT from an unsigned raw transaction").args(&[
		args::arg("raw-tx", "the raw transaction in hex").required(false),
		args::flag("v2", "create a PSBT version 2 (BIP-370) instead of version 0"),
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
	let psbt = if args.is_present("v2") {
		AnyPsbt::V2(psbt_v0_to_v2(psbt))
	} else {
		AnyPsbt::V0(psbt)
	};

	write_psbt(args, &psbt.serialize(), None);
}

fn cmd_decode<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("decode", "decode a PSBT to JSON")
		.arg(args::arg("psbt", "the PSBT file or raw PSBT in base64/hex").required(false))
}

fn exec_decode<'a>(args: &clap::ArgMatches<'a>) {
	let input = util::arg_or_stdin(args, "psbt");
	let (raw_psbt, _) = file_or_raw(input.as_ref());

	match AnyPsbt::deserialize(&raw_psbt) {
		AnyPsbt::V0(psbt) => args.print_output(&hal::GetInfo::get_info(&psbt, args.network())),
		AnyPsbt::V2(psbt) => args.print_output(&hal::GetInfo::get_info(&psbt, args.network())),
	}
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
		// input values only for PSBTv2
		args::opt("sequence", "the sequence number (PSBTv2 only)")
			.display_order(99)
			.next_line_help(true),
		args::opt("required-time-locktime", "the minimum time-based locktime (PSBTv2 only)")
			.display_order(99)
			.next_line_help(true),
		args::opt("required-height-locktime", "the minimum height-based locktime (PSBTv2 only)")
			.display_order(99)
			.next_line_help(true),
		//
		// output values
		// (omitted) redeem-script
		// (omitted) witness-script
		// (omitted) hd-keypaths
		// (omitted) hd-keypaths-add
		// output values only for PSBTv2
		args::opt("amount", "the output amount in satoshi (PSBTv2 only)")
			.display_order(99)
			.next_line_help(true),
		args::opt("script-pubkey", "the output scriptPubkey in hex (PSBTv2 only)")
			.display_order(99)
			.next_line_help(true),
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

/// Exit if any of the given PSBTv2-only arguments is present.
fn reject_v2_only_args<'a>(args: &clap::ArgMatches<'a>, names: &[&str]) {
	for name in names {
		if args.is_present(name) {
			exit!("--{} can only be used on a PSBTv2", name);
		}
	}
}

/// Edit the fields that exist in both PSBTv0 and PSBTv2 inputs.
///
/// The two input types have different types for some fields, so we use a
/// macro to apply the same edits to both.
macro_rules! edit_input_common {
	($input:expr, $args:expr, $bip32_field:ident, $convert_bip32_key:expr, $convert_sighash:expr) => {{
		let input = $input;
		let args = $args;

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
			let sht = hal::psbt::ecdsa_sighashtype_from_string(&sht).need("invalid sighash string");
			input.sighash_type = Some($convert_sighash(sht));
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
			input.$bip32_field = csv.split(",").map(parse_hd_keypath_triplet)
				.map(|(pk, src)| ($convert_bip32_key(pk), src)).collect();
		}
		if let Some(triplets) = args.values_of("hd-keypaths-add") {
			for (pk, pair) in triplets.map(parse_hd_keypath_triplet) {
				if input.$bip32_field.insert($convert_bip32_key(pk), pair).is_some() {
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
	}}
}

/// Edit the fields that exist in both PSBTv0 and PSBTv2 outputs.
macro_rules! edit_output_common {
	($output:expr, $args:expr, $bip32_field:ident, $convert_bip32_key:expr) => {{
		let output = $output;
		let args = $args;

		if let Some(hex) = args.value_of("redeem-script") {
			let raw = hex::decode(&hex).need("invalid redeem-script hex");
			output.redeem_script = Some(raw.into());
		}

		if let Some(hex) = args.value_of("witness-script") {
			let raw = hex::decode(&hex).need("invalid witness-script hex");
			output.witness_script = Some(raw.into());
		}

		if let Some(csv) = args.value_of("hd-keypaths") {
			output.$bip32_field = csv.split(",").map(parse_hd_keypath_triplet)
				.map(|(pk, src)| ($convert_bip32_key(pk), src)).collect();
		}
		if let Some(triplets) = args.values_of("hd-keypaths-add") {
			for (pk, pair) in triplets.map(parse_hd_keypath_triplet) {
				if output.$bip32_field.insert($convert_bip32_key(pk), pair).is_some() {
					exit!("public key {} is already in HD keypaths", &pk);
				}
			}
		}
	}}
}

const V2_ONLY_INPUT_ARGS: &[&str] = &["sequence", "required-time-locktime", "required-height-locktime"];
const V2_ONLY_OUTPUT_ARGS: &[&str] = &["amount", "script-pubkey"];

fn edit_input<'a>(
	idx: usize,
	args: &clap::ArgMatches<'a>,
	psbt: &mut AnyPsbt,
) {
	match psbt {
		AnyPsbt::V0(psbt) => {
			reject_v2_only_args(args, V2_ONLY_INPUT_ARGS);
			let input = psbt.inputs.get_mut(idx).need("input index out of range");
			edit_input_common!(input, args, bip32_derivation, |pk| pk, |sht| sht);
		},
		AnyPsbt::V2(psbt) => {
			let input = psbt.inputs.get_mut(idx).need("input index out of range");
			edit_input_common!(
				&mut *input, args, bip32_derivations,
				|pk| PublicKey::new(pk),
				|sht: bitcoin::psbt::PsbtSighashType| psbt_v2::PsbtSighashType::from_u32(sht.to_u32())
			);

			if let Some(seq) = args.value_of("sequence") {
				let seq = seq.parse::<u32>().need("invalid sequence number");
				input.sequence = Some(bitcoin::Sequence::from_consensus(seq));
			}

			if let Some(lt) = args.value_of("required-time-locktime") {
				let lt = lt.parse::<u32>().need("invalid time locktime");
				input.min_time = Some(absolute::Time::from_consensus(lt)
					.need("invalid time locktime"));
			}

			if let Some(lt) = args.value_of("required-height-locktime") {
				let lt = lt.parse::<u32>().need("invalid height locktime");
				input.min_height = Some(absolute::Height::from_consensus(lt)
					.need("invalid height locktime"));
			}
		},
	}
}

fn edit_output<'a>(idx: usize, args: &clap::ArgMatches<'a>, psbt: &mut AnyPsbt) {
	match psbt {
		AnyPsbt::V0(psbt) => {
			reject_v2_only_args(args, V2_ONLY_OUTPUT_ARGS);
			let output = psbt.outputs.get_mut(idx).need("output index out of range");
			edit_output_common!(output, args, bip32_derivation, |pk| pk);
		},
		AnyPsbt::V2(psbt) => {
			let output = psbt.outputs.get_mut(idx).need("output index out of range");
			edit_output_common!(&mut *output, args, bip32_derivations, |pk| PublicKey::new(pk));

			if let Some(amount) = args.value_of("amount") {
				let sat = amount.parse::<u64>().need("invalid amount");
				output.amount = bitcoin::Amount::from_sat(sat);
			}

			if let Some(hex) = args.value_of("script-pubkey") {
				let raw = hex::decode(&hex).need("invalid script-pubkey hex");
				output.script_pubkey = raw.into();
			}
		},
	}
}

fn exec_edit<'a>(args: &clap::ArgMatches<'a>) {
	let input = util::arg_or_stdin(args, "psbt");
	let (raw, source) = file_or_raw(input.as_ref());
	let mut psbt = AnyPsbt::deserialize(&raw);

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

	write_psbt(args, &psbt.serialize(), Some(source));
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
	// The finalizer works on PSBTv0, but the resulting transaction is the same.
	let psbt = AnyPsbt::deserialize(&raw).into_v0();

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
	let mut parts: Box<dyn Iterator<Item = AnyPsbt>> = if let Some(values) = args.values_of("psbts") {
		Box::new(values.into_iter().map(|f| {
			let (raw, _) = file_or_raw(&f);
			AnyPsbt::deserialize(&raw)
		}))
	} else {
		// Read from stdin.
		let stdin_lock = stdin.lock();
		let buf = io::BufReader::new(stdin_lock);
		Box::new(buf.lines().take_while(|l| l.is_ok() && !l.as_ref().unwrap().is_empty()).map(|l| {
			let (raw, _) = file_or_raw(&l.unwrap());
			AnyPsbt::deserialize(&raw)
		}))
	};

	let mut merged = parts.next().unwrap();
	for (idx, part) in parts.enumerate() {
		if part.version() != merged.version() {
			exit!("PSBT #{} has version {} while the first has version {}; \
				use `hal psbt convert` to convert them to the same version",
				idx, part.version(), merged.version(),
			);
		}
		match (&mut merged, part) {
			(AnyPsbt::V0(merged), AnyPsbt::V0(part)) => {
				if part.unsigned_tx != merged.unsigned_tx {
					exit!("PSBTs are not compatible");
				}
				merged.combine(part).need(&format!("error merging PSBT #{}", idx));
			},
			(AnyPsbt::V2(merged), AnyPsbt::V2(part)) => {
				let combined = merged.clone().combine_with(part)
					.need(&format!("error merging PSBT #{}", idx));
				*merged = combined;
			},
			_ => unreachable!("versions checked above"),
		}
	}

	write_psbt(args, &merged.serialize(), None);
}

fn cmd_rawsign<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("rawsign", "sign a psbt with private key and add sig to partial sigs").args(&[
		args::arg("psbt", "PSBT to sign, either base64/hex or a file path").required(true),
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
	let input = args.value_of("psbt").need("no PSBT provided");
	let (raw, source) = file_or_raw(input);
	let mut psbt = AnyPsbt::deserialize(&raw);
	// The sighash is calculated on the PSBTv0 representation.
	let psbt_v0 = psbt.to_v0();

	let sk = args.need_privkey("priv-key").inner;
	let i = args.value_of("input-idx").need("Input index not provided")
		.parse::<usize>().need("input-idx must be a positive integer");
	let compressed = args.value_of("compressed").unwrap()
		.parse::<bool>().need("Compressed must be boolean");

	if i >= psbt_v0.inputs.len() {
		exit!("PSBT input index out of range")
	}

	let mut cache = bitcoin::sighash::SighashCache::new(&psbt_v0.unsigned_tx);

	let pk = secp256k1::PublicKey::from_secret_key(&SECP, &sk);
	let pk = bitcoin::PublicKey { compressed, inner: pk };
	let msg = psbt_v0.sighash_msg(i, &mut cache, None)
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
			exit!("Signing taproot transactions is not yet suppported")
		},
	};

	let sighashtype = psbt_v0.inputs[i].sighash_type
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
	match psbt {
		AnyPsbt::V0(ref mut psbt) => {
			psbt.inputs[i].partial_sigs.insert(pk, sig);
		},
		AnyPsbt::V2(ref mut psbt) => {
			psbt.inputs[i].partial_sigs.insert(pk, sig);
		},
	}
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

fn cmd_convert<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("convert", "convert a PSBT between version 0 (BIP-174) and version 2 (BIP-370)")
		.args(&[
			args::arg("psbt", "PSBT to convert, either base64/hex or a file path").required(false),
			args::flag("v0", "convert to PSBT version 0"),
			args::flag("v2", "convert to PSBT version 2"),
			args::opt("output", "where to save the resulting PSBT file")
				.short("o"),
			args::flag("raw-stdout", "output the raw bytes of the result to stdout")
				.short("r"),
		])
		.long_about(r#"
Convert a PSBT between version 0 (BIP-174) and version 2 (BIP-370).

If neither --v0 nor --v2 is given, the PSBT is converted to the other version.

Converting to version 0 requires the locktime requirements of the inputs to be
compatible and drops the modifiable flags. The output is printed in the same
encoding as the input (hex or base64), or in base64 when the input was a file.
"#)
}

fn exec_convert<'a>(args: &clap::ArgMatches<'a>) {
	let input = util::arg_or_stdin(args, "psbt");
	let (raw, source) = file_or_raw(input.as_ref());
	let psbt = AnyPsbt::deserialize(&raw);

	let target = match (args.is_present("v0"), args.is_present("v2")) {
		(true, true) => exit!("can't use both --v0 and --v2"),
		(true, false) => 0,
		(false, true) => 2,
		(false, false) => match psbt {
			AnyPsbt::V0(_) => 2,
			AnyPsbt::V2(_) => 0,
		},
	};
	let converted = match target {
		0 => AnyPsbt::V0(psbt.into_v0()),
		2 => AnyPsbt::V2(psbt.into_v2()),
		_ => unreachable!(),
	};

	let source = match source {
		PsbtSource::File => PsbtSource::Base64,
		s => s,
	};
	write_psbt(args, &converted.serialize(), Some(source));
}
