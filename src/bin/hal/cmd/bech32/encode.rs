use bech32lib::{encode, CheckBase32, FromBase32, ToBase32};
use clap;
use hex;

use cmd;
use hal;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("encode", "encode bech32 format").args(&[
		cmd::opt_yaml(),
		cmd::opt("no-convert", "Do not convert payload to base32").required(false),
		cmd::arg("hrp", "human-readable part").takes_value(true).required(true),
		cmd::arg(
			"payload-hex",
			"hex-encoded payload bytes, 8-bit values\nunless --no-convert is specified",
		)
		.takes_value(true)
		.required(true),
	])
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	let hrp = matches.value_of("hrp").expect("missing required argument");
	let hex = matches.value_of("payload-hex").expect("missing required argument");

	let payload: Vec<u8> = hex::decode(hex).expect("Invalid hex");

	let payload_base32 = if matches.is_present("no-convert") {
		payload.check_base32().expect("Invalid base32 payload")
	} else {
		payload.to_base32()
	};

	let result = encode(hrp, payload_base32.to_vec());
	if result.is_err() {
		panic!("Encode failure: {:?}", result.unwrap_err());
	}

	let payload_bytes: Vec<u8> = payload_base32.to_vec().iter().map(|b| b.to_u8()).collect();

	let info = hal::bech32::Bech32Info {
		bech32: result.unwrap(),
		hrp: hrp.to_string(),
		payload: payload_bytes.into(),
		payload_base256: match Vec::<u8>::from_base32(&payload_base32) {
			Ok(payload_base256) => Some(payload_base256.into()),
			Err(_) => None,
		},
	};

	cmd::print_output(matches, &info)
}
