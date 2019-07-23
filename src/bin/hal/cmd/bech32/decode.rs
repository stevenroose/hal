use bech32lib::{decode, FromBase32};
use clap;

use cmd;
use hal;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("decode", "decode bech32 format").args(&[
		cmd::opt_yaml(),
		cmd::opt(
			"convert-bits",
			"Attempt to convert payload from 5-bit to 8-bit values.\nNOTE: Does not work for BIP-173 addresses."
		)
		.short("c")
		.required(false),
		cmd::arg("string", "a bech32 string").takes_value(true).required(true),
	])
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	let s = matches.value_of("string").expect("missing required argument");
	let result = decode(&s);
	if result.is_err() {
		panic!("Decode failure: {:?}", result.unwrap_err());
	}
	let (hrp, payload_base32) = result.unwrap();
	let payload_bytes: Vec<u8> = payload_base32.to_vec().iter().map(|b| b.to_u8()).collect();
	let mut info = hal::bech32::Bech32Info {
		bech32: s.to_string(),
		hrp,
		payload: payload_bytes.into(),
		payload_base256: None,
	};
	if matches.is_present("convert-bits") {
		let convert_result = Vec::<u8>::from_base32(&payload_base32);
		if convert_result.is_err() {
			panic!("Error converting payload to 8-bit {:?}", convert_result.unwrap_err());
		}
		info.payload_base256 = Some(convert_result.unwrap().into());
	}
	cmd::print_output(matches, &info)
}
