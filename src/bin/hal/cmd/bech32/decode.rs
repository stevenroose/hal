use bech32lib::{decode, FromBase32};
use clap;

use cmd;
use hal;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("decode", "decode bech32 format").args(&[
		cmd::opt_yaml(),
		cmd::opt("bytes", "Display payload bytes").required(false),
        cmd::opt("convert-bits", "Attempt to convert payload to 8-bit values.\nNOTE: Does not work for BIP-173 addresses.").short("c").required(false),
		cmd::arg("string", "a bech32 string").takes_value(true).required(true),
	])
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
    let s = matches.value_of("string").expect("missing required argument");
    let result = decode(&s);
    if result.is_err() {
        panic!("Decode failure: {:?}", result.unwrap_err());
    }
    let (hrp, b32_payload) = result.unwrap();
	let mut info = hal::bech32::Bech32Info {
		hrp,
		payload_bytes: None,
		payload_hex: None,
	};
    let payload: Vec<u8> = if matches.is_present("convert-bits") {
        let convert_result = Vec::<u8>::from_base32(&b32_payload);
        if convert_result.is_err() {
            panic!("Error converting payload to 8-bit {:?}", convert_result.unwrap_err());
        }
        convert_result.unwrap()
    } else {
        b32_payload.iter().map(|b| b.to_u8()).collect()
    };
    if matches.is_present("bytes") {
        info.payload_bytes = Some(payload.to_vec());
    }
    info.payload_hex = Some(payload.into());
	cmd::print_output(matches, &info)
}
