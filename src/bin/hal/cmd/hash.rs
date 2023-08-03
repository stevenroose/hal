use std::io::Write;

use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::{sha256, sha256d, Hash};

use crate::prelude::*;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("hash", "commands to hash data")
		.subcommand(cmd_sha256())
		.subcommand(cmd_sha256d())
}

pub fn execute<'a>(args: &clap::ArgMatches<'a>) {
	match args.subcommand() {
		("sha256", Some(ref m)) => exec_sha256(&m),
		("sha256d", Some(ref m)) => exec_sha256d(&m),
		(_, _) => unreachable!("clap prints help"),
	};
}

fn cmd_sha256<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("sha256", "hash input with SHA-256")
		.arg(args::arg("hex", "the input bytes in hex to hash").required(true))
		.arg(args::opt("raw-stdout", "output the raw bytes of the result to stdout")
			.short("r")
			.required(false))
}

fn exec_sha256<'a>(args: &clap::ArgMatches<'a>) {
	let hex = args.value_of("hex").need("no input bytes given");
	let bytes = Vec::<u8>::from_hex(&hex).need("invalid hex");

	let ret = sha256::Hash::hash(&bytes);
	if args.is_present("raw-stdout") {
		::std::io::stdout().write_all(&ret[..]).unwrap();
	} else {
		print!("{}", ret);
	}
}

fn cmd_sha256d<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("sha256d", "hash input with double SHA-256")
		.arg(args::arg("hex", "the input bytes in hex to hash").required(true))
		.arg(args::opt("raw-stdout", "output the raw bytes of the result to stdout")
			.short("r")
			.required(false))
}

fn exec_sha256d<'a>(args: &clap::ArgMatches<'a>) {
	let hex = args.value_of("hex").need("no input bytes given");
	let bytes = Vec::<u8>::from_hex(&hex).need("invalid hex");

	let ret = sha256d::Hash::hash(&bytes);
	if args.is_present("raw-stdout") {
		::std::io::stdout().write_all(&ret[..]).unwrap();
	} else {
		print!("{}", ret);
	}
}

