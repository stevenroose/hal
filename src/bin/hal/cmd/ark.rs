use std::str::FromStr;

use bitcoin::{bech32, Network};
use clap;

use hal::GetInfo;
use hal::ark::{ArkAddressInfo, ArkadeAddressInfo};
use secp256k1::XOnlyPublicKey;

use crate::prelude::*;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("ark", "everything Ark").subcommand(
		cmd::subcommand_group("address", "handle Ark addresses")
			.subcommand(cmd_address_inspect()),
	)
}

pub fn execute<'a>(args: &clap::ArgMatches<'a>) {
	match args.subcommand() {
		("address", Some(ref args)) => match args.subcommand() {
			("inspect", Some(ref m)) => exec_address_inspect(&m),
			(_, _) => unreachable!("clap prints help"),
		},
		(_, _) => unreachable!("clap prints help"),
	};
}

fn cmd_address_inspect<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("inspect", "inspect an Ark address")
		.arg(args::arg("address", "the address").required(true))
}

const HRP_ARK: bech32::Hrp = bech32::Hrp::parse_unchecked("ark");
const HRP_TARK: bech32::Hrp = bech32::Hrp::parse_unchecked("tark");

fn arkade_info(addr: &str) -> ArkadeAddressInfo {
	let (hrp, payload) = bech32::decode(addr).need("invalid address encoding");
	let testnet = match hrp {
		h if h == HRP_ARK => false,
		h if h == HRP_TARK => true,
		// shouldn't happen because of earlier check
		h => exit!("invalid HRP: {}", h),
	};

	if payload.is_empty() {
		exit!("invalid Arkade address");
	}
	let ver = payload[0];
	if ver == 0 {
		if payload.len() != 1 + 32 + 32 {
			exit!("invalid Arkade address");
		}

		let user_pubkey = XOnlyPublicKey::from_slice(&payload[1..33])
			.need("invalid Arkade address");
		let server_pubkey = XOnlyPublicKey::from_slice(&payload[33..65])
			.need("invalid Arkade address");

		ArkadeAddressInfo { testnet, user_pubkey, server_pubkey }
	} else {
		exit!("unknown Arkade address version");
	}
}

fn exec_address_inspect<'a>(args: &clap::ArgMatches<'a>) {
	let address_str = args.value_of("address").need("no address provided");

	args.print_output(&address_info(address_str))
}

fn address_info(addr: &str) -> ArkAddressInfo {
	// we could recognize bark/arkade by parsing into bech32 and taking
	// the first field element, but it's equivalent to the prefix and
	// this is a lot more concise

	if addr.starts_with("ark1q") || addr.starts_with("tark1q") {
		// arkade address
		ArkAddressInfo::Arkade(arkade_info(addr))
	} else {
		let addr = ark::Address::from_str(addr).need("invalid address");
		// network doesn't matter
		ArkAddressInfo::Bark(addr.get_info(Network::Regtest))
	}
}

