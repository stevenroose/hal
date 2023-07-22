use std::io::Write;

use bitcoin::secp256k1::rand::{self, RngCore};

use crate::prelude::*;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("random", "generate random data")
		.subcommand(cmd_bytes())
}

pub fn execute<'a>(args: &clap::ArgMatches<'a>) {
	match args.subcommand() {
		("bytes", Some(ref m)) => exec_bytes(&m),
		(_, _) => unreachable!("clap prints help"),
	};
}

fn cmd_bytes<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("bytes", "generate random bytes")
		.arg(args::arg("number", "the number of bytes").required(true))
		.arg(args::opt("raw-stdout", "output the raw bytes of the result to stdout")
			.short("r")
			.required(false))
}

fn exec_bytes<'a>(args: &clap::ArgMatches<'a>) {
	let nb = args.value_of("number").need("no number of bytes given")
		.parse::<usize>()
		.need("invalid number of bytes");
	let mut bytes = vec![0u8; nb];
	rand::thread_rng().fill_bytes(&mut bytes);
	
	if args.is_present("raw-stdout") {
		::std::io::stdout().write_all(&bytes).unwrap();
	} else {
		print!("{}", hex::encode(&bytes));
	}
}

