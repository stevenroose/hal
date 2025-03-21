
use std::str::FromStr;
use crate::prelude::*;
use secp256k1_zkp_musig as zkpmusig;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("musig", "use the MuSig2 multisignature protocol")
		.subcommand(cmd_aggregate())
}

pub fn execute<'a>(args: &clap::ArgMatches<'a>) {
	match args.subcommand() {
		("aggregate", Some(ref m)) => exec_aggregate(&m),
		(_, _) => unreachable!("clap prints help"),
	};
}

fn cmd_aggregate<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("aggregate", "aggregate public keys in a MuSig2 compatible way")
		.arg(args::flag(
			"ordered", "aggregate in the specified order instead of ordering lexicographically",
		))
		.arg(args::arg("pubkeys", "list of public keys in hex").required(true).multiple(true))
}

fn exec_aggregate<'a>(args: &clap::ArgMatches<'a>) {
	let mut pks = Vec::with_capacity(2);
	for arg in args.values_of("pubkeys").need("no pubkeys provided") {
		let pk = bitcoin::PublicKey::from_str(&arg).unwrap_or_else(|_| {
			exit!("invalid public key provided: {}", arg);
		});
		pks.push(zkpmusig::PublicKey::from_slice(&pk.inner.serialize()).unwrap());
	}

	if !args.is_present("ordered") {
		//TODO(stevenroose) is this lexicographically
		pks.sort_by_key(|k| k.serialize());
	}

	let secp = zkpmusig::Secp256k1::new();
	let agg = zkpmusig::MusigKeyAggCache::new(&secp, &pks[..]);
	print!("{}", agg.agg_pk());
}
