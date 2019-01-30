use bitcoin::Address;
use clap;
use secp256k1;

use hal;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	clap::SubCommand::with_name("create")
		.about("create addresses")
		.arg(
			clap::Arg::with_name("pubkey")
				.long("pubkey")
				.help("a public key in hex")
				.takes_value(true)
				.required(false),
		)
		.arg(
			clap::Arg::with_name("script")
				.long("script")
				.help("a script in hex")
				.takes_value(true)
				.required(false),
		)
		.arg(
			clap::Arg::with_name("testnet")
				.long("testnet")
				.short("t")
				.help("for testnet usage")
				.takes_value(false)
				.required(false),
		)
		.arg(
			clap::Arg::with_name("yaml")
				.long("yaml")
				.short("y")
				.help("print output in YAML")
				.takes_value(false)
				.required(false),
		)
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	let network = if matches.is_present("testnet") {
		bitcoin::Network::Testnet
	} else {
		bitcoin::Network::Bitcoin
	};

	let created = if let Some(pubkey_hex) = matches.value_of("pubkey") {
		let pubkey_bytes = hex::decode(pubkey_hex).expect("invalid pubkey hex");
		let pubkey = secp256k1::PublicKey::from_slice(&pubkey_bytes).expect("invalid pubkey");

		hal::address::CreatedAddresses{
			p2pkh: Some(Address::p2pkh(&pubkey, network).to_string()),
			p2wpkh: Some(Address::p2wpkh(&pubkey, network).to_string()),
			p2shwpkh: Some(Address::p2shwpkh(&pubkey, network).to_string()),
			..Default::default()
		}
	} else if let Some(script_hex) = matches.value_of("script") {
		let script_bytes = hex::decode(script_hex).expect("invalid script hex");
		let script = script_bytes.into();

		hal::address::CreatedAddresses {
			p2sh: Some(Address::p2sh(&script, network).to_string()),
			p2wsh: Some(Address::p2wsh(&script, network).to_string()),
			p2shwsh: Some(Address::p2shwsh(&script, network).to_string()),
			..Default::default()
		}
	} else {
		panic!("Can't create addresses without a pubkey");
	};

	if matches.is_present("yaml") {
		serde_yaml::to_writer(::std::io::stdout(), &created).unwrap();
	} else {
		serde_json::to_writer_pretty(::std::io::stdout(), &created).unwrap();
	}
}
