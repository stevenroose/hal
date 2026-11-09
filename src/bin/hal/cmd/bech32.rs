
use bitcoin::bech32;
use bitcoin::bech32::primitives::decode::CheckedHrpstring;
use clap;
use hex;

use hal;
use crate::prelude::*;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("bech32", "encode and decode the bech32 format")
		.subcommand(cmd_encode())
		.subcommand(cmd_decode())
}

pub fn execute<'a>(args: &clap::ArgMatches<'a>) {
	match args.subcommand() {
		("encode", Some(ref m)) => exec_encode(&m),
		("decode", Some(ref m)) => exec_decode(&m),
		(_, _) => unreachable!("clap prints help"),
	};
}

fn cmd_encode<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("encode", "encode bech32 format")
		.arg(args::arg("hrp", "human-readable part").required(true))
		.arg(args::arg("payload-hex", "hex-encoded payload bytes"))
		.arg(args::flag("legacy", "encode using legacy bech32, not bech32m"))
}

fn exec_encode<'a>(args: &clap::ArgMatches<'a>) {
	let hrp = args.value_of("hrp").need("missing required argument");
	let hrp = bech32::Hrp::parse(hrp).need("invalid HRP");
	let hex = util::arg_or_stdin(args, "payload-hex");

	let payload = hex::decode(hex.as_ref()).need("invalid hex");
	let (bech32, variant) = if args.is_present("legacy") {
		(bech32::encode::<bech32::Bech32>(hrp, &payload).need("encode failure"), "bech32")
	} else {
		(bech32::encode::<bech32::Bech32m>(hrp, &payload).need("encode failure"), "bech32m")
	};
	let info = hal::bech32::Bech32Info {
		bech32,
		variant: Some(variant.to_owned()),
		hrp: hrp.to_string(),
		payload: payload.into(),
	};

	args.print_output(&info)
}

fn cmd_decode<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("decode", "decode bech32 format")
		.arg(args::arg("bech32", "a bech32 string"))
}

fn exec_decode<'a>(args: &clap::ArgMatches<'a>) {
	let s = util::arg_or_stdin(args, "bech32");

	let (hrp, payload) = bech32::decode(&s).need("invalid bech32");

	let variant = if CheckedHrpstring::new::<bech32::Bech32>(&s).is_ok() {
		Some("bech32".to_owned())
	} else if CheckedHrpstring::new::<bech32::Bech32m>(&s).is_ok() {
		Some("bech32m".to_owned())
	} else {
		None
	};

	let info = hal::bech32::Bech32Info {
		bech32: s.to_string(),
		variant: variant,
		hrp: hrp.to_string(),
		payload: payload.into(),
	};

	args.print_output(&info)
}
