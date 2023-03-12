use bitcoin::bech32::{decode, encode, CheckBase32, FromBase32, ToBase32, Variant};
use clap;
use hex;

use hal;
use crate::{cmd, util};

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("bech32", "encode and decode the bech32 format")
		.subcommand(cmd_encode())
		.subcommand(cmd_decode())
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	match matches.subcommand() {
		("encode", Some(ref m)) => exec_encode(&m),
		("decode", Some(ref m)) => exec_decode(&m),
		(_, _) => unreachable!("clap prints help"),
	};
}

fn cmd_encode<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("encode", "encode bech32 format").args(&[
		cmd::opt_yaml(),
		cmd::opt("no-convert", "Do not convert payload to base32").required(false),
		cmd::arg("hrp", "human-readable part").takes_value(true).required(true),
		cmd::arg(
			"payload-hex",
			"hex-encoded payload bytes, 8-bit values\nunless --no-convert is specified",
		)
		.takes_value(true)
		.required(false),
	])
}

fn exec_encode<'a>(matches: &clap::ArgMatches<'a>) {
	let hrp = matches.value_of("hrp").expect("missing required argument");
	let hex = util::arg_or_stdin(matches, "payload-hex");

	let payload: Vec<u8> = hex::decode(hex.as_ref()).expect("invalid hex");

	let payload_base32 = if matches.is_present("no-convert") {
		payload.check_base32().expect("invalid base32 payload")
	} else {
		payload.to_base32()
	};

	let bech32 = encode(hrp, payload_base32.to_vec(), Variant::Bech32).expect("encode failure");
	let payload_as_u8: Vec<u8> = payload_base32.to_vec().iter().map(|b| b.to_u8()).collect();

	let info = hal::bech32::Bech32Info {
		bech32,
		hrp: hrp.to_string(),
		payload: payload_as_u8.into(),
		payload_bytes: match Vec::<u8>::from_base32(&payload_base32) {
			Ok(p) => Some(p.into()),
			Err(_) => None,
		},
	};

	cmd::print_output(matches, &info)
}

fn cmd_decode<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("decode", "decode bech32 format").args(&[
		cmd::opt_yaml(),
		cmd::opt(
			"convert-bits",
			"Attempt to convert payload from 5-bit to 8-bit values.\nNOTE: Does not work for BIP-173 addresses."
		)
		.short("c")
		.required(false),
		cmd::arg("string", "a bech32 string").takes_value(true).required(false),
	])
}

fn exec_decode<'a>(matches: &clap::ArgMatches<'a>) {
	let s = util::arg_or_stdin(matches, "string");

	let (hrp, payload_base32, _variant) = decode(&s).expect("decode failure");
	let payload_as_u8: Vec<u8> = payload_base32.to_vec().iter().map(|b| b.to_u8()).collect();

	let info = hal::bech32::Bech32Info {
		bech32: s.to_string(),
		hrp,
		payload: payload_as_u8.into(),
		payload_bytes: if matches.is_present("convert-bits") {
			let converted =
				Vec::<u8>::from_base32(&payload_base32).expect("error converting payload to 8-bit");
			Some(converted.into())
		} else {
			None
		},
	};

	cmd::print_output(matches, &info)
}
