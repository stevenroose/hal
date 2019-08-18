use bitcoin::bech32::{encode, CheckBase32, FromBase32, ToBase32};
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

	let payload: Vec<u8> = hex::decode(hex).expect("invalid hex");

	let payload_base32 = if matches.is_present("no-convert") {
		payload.check_base32().expect("invalid base32 payload")
	} else {
		payload.to_base32()
	};

	let bech32 = encode(hrp, payload_base32.to_vec()).expect("encode failure");
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
