use bech32lib::{encode, CheckBase32, ToBase32};
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

	let result = if matches.is_present("no-convert") {
		let checked_payload = payload.to_vec().check_base32().expect("Invalid base32 payload");
		encode(hrp, checked_payload)
	} else {
		encode(hrp, payload.to_vec().to_base32())
	};
	if result.is_err() {
		panic!("Encode failure: {:?}", result.unwrap_err());
	}

	let info = hal::bech32::Bech32Info {
		bech32: result.unwrap(),
		hrp: hrp.to_string(),
		payload_bytes: None,
		payload_hex: Some(payload.into()),
	};

	cmd::print_output(matches, &info)
}
