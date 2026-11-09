use bitcoin::consensus::encode::deserialize;
use bitcoin::pow::{CompactTarget, Target};
use bitcoin::block;

use hal::GetInfo;
use crate::prelude::*;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("pow", "proof-of-work targets and difficulty")
		.subcommand(cmd_target())
		.subcommand(cmd_next_target())
}

pub fn execute<'a>(args: &clap::ArgMatches<'a>) {
	match args.subcommand() {
		("target", Some(ref m)) => exec_target(&m),
		("next-target", Some(ref m)) => exec_next_target(&m),
		(_, _) => unreachable!("clap prints help"),
	};
}

fn cmd_target<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("target", "inspect a proof-of-work target")
		.arg(args::arg("target", "the compact target (bits) as a decimal or 0x-prefixed hex \
			number, or the full target as a 64-character hex number").required(true))
		.long_about(r#"
Inspect a proof-of-work target: shows the compact encoding (bits), the full
256-bit target, the difficulty and the expected work.

The difficulty depends on the network's maximum target, so use the network
flags for networks other than mainnet.
"#)
}

/// Parse a compact target from a decimal or 0x-prefixed hex number.
fn parse_bits(s: &str) -> Option<CompactTarget> {
	let bits = if let Some(hex) = s.strip_prefix("0x") {
		u32::from_str_radix(hex, 16).ok()?
	} else {
		s.parse::<u32>().ok()?
	};
	Some(CompactTarget::from_consensus(bits))
}

fn exec_target<'a>(args: &clap::ArgMatches<'a>) {
	let s = args.value_of("target").need("no target provided");
	let network = args.network();

	if s.len() == 64 {
		let target = Target::from_unprefixed_hex(s).need("invalid target hex");
		args.print_output(&target.get_info(network));
	} else {
		let bits = parse_bits(s).need("invalid compact target: expected decimal or 0x-prefixed hex");
		args.print_output(&bits.get_info(network));
	}
}

fn cmd_next_target<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("next-target", "calculate the target of the next difficulty period")
		.arg(args::arg("first-header", "the raw header of the first block of the current \
			difficulty period in hex").required(true))
		.arg(args::arg("last-header", "the raw header of the last block of the current \
			difficulty period in hex").required(true))
		.long_about(r#"
Calculate the target of the next difficulty period from the first and last
block header of the current period, as Bitcoin Core does.

Use the network flags for networks other than mainnet.
"#)
}

fn exec_next_target<'a>(args: &clap::ArgMatches<'a>) {
	let parse_header = |name: &str| -> block::Header {
		let hex = args.value_of(name).need(&format!("no {} provided", name));
		let raw = hex::decode(hex).need(&format!("invalid {} hex", name));
		deserialize(&raw).need(&format!("invalid {} format", name))
	};
	let first = parse_header("first-header");
	let last = parse_header("last-header");
	if last.time < first.time {
		exit!("the last header has an earlier timestamp than the first header");
	}

	let next = CompactTarget::from_header_difficulty_adjustment(first, last, args.network());
	args.print_output(&next.get_info(args.network()));
}
