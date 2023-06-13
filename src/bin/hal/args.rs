
use std::borrow::Borrow;

use bitcoin::Network;

use crate::exit;

/// Construct a new command option.
pub fn opt<'a>(name: &'a str, help: &'a str) -> clap::Arg<'a, 'a> {
	clap::Arg::with_name(name).long(name).help(help)
}

/// Construct a new positional argument.
pub fn arg<'a>(name: &'a str, help: &'a str) -> clap::Arg<'a, 'a> {
	clap::Arg::with_name(name).help(help).takes_value(true)
}

pub fn opts_networks() -> Vec<clap::Arg<'static, 'static>> {
	vec![
		clap::Arg::with_name("testnet")
			.long("testnet")
			.short("t")
			.help("run in testnet mode")
			.takes_value(false)
			.required(false),
		clap::Arg::with_name("regtest")
			.long("regtest")
			.help("run in regtest mode")
			.takes_value(false)
			.required(false),
	]
}

pub fn opt_yaml() -> clap::Arg<'static, 'static> {
	clap::Arg::with_name("yaml")
		.long("yaml")
		.short("y")
		.help("print output in YAML instead of JSON")
		.takes_value(false)
		.required(false)
}

pub trait ArgMatchesExt<'a>: Borrow<clap::ArgMatches<'a>> {
	fn network(&self) -> bitcoin::Network {
		if self.borrow().is_present("testnet") {
			Network::Testnet
		} else if self.borrow().is_present("regtest") {
			Network::Regtest
		} else {
			Network::Bitcoin
		}
	}

	fn out_yaml(&self) -> bool {
		self.borrow().is_present("yaml")
	}

	fn print_output<T: serde::Serialize>(&self, out: &T) {
		if self.out_yaml() {
			serde_yaml::to_writer(::std::io::stdout(), &out).unwrap();
		} else {
			serde_json::to_writer_pretty(::std::io::stdout(), &out).unwrap();
		}
	}
}

impl<'a> ArgMatchesExt<'a> for clap::ArgMatches<'a> {}
