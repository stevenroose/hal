use bitcoin::util::address::Payload;
use bitcoin::Address;
use clap;
use hal;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	clap::SubCommand::with_name("inspect")
		.about("inspect addresses")
		.arg(clap::Arg::with_name("address").help("the address").takes_value(true).required(true))
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
	let address_str = matches.value_of("address").expect("no address provided");
	let address: Address = address_str.parse().expect("invalid address format");
	let script_pk = address.script_pubkey();

	let mut info = hal::address::AddressInfo {
		network: address.network,
		script_pub_key: hal::tx::OutputScriptInfo {
			hex: Some(script_pk.to_bytes().into()),
			asm: Some(format!("{:?}", script_pk)), //TODO(stevenroose) asm
			address: None,
			type_: None,
		},
		type_: None,
		pubkey_hash: None,
		script_hash: None,
		witness_program_version: None,
	};

	match address.payload {
		Payload::Pubkey(_) => unreachable!("address doesn't exist"),
		Payload::PubkeyHash(ref pkh) => {
			info.type_ = Some("p2pkh".to_owned());
			info.pubkey_hash = Some(pkh.to_bytes()[..].into());
		}
		Payload::ScriptHash(ref sh) => {
			info.type_ = Some("p2sh".to_owned());
			info.script_hash = Some(sh.to_bytes()[..].into());
		}
		Payload::WitnessProgram(ref wp) => {
			let version = wp.version().to_u8() as usize;
			info.witness_program_version = Some(version);

			if version == 0 {
				if wp.program().len() == 20 {
					info.type_ = Some("p2wpkh".to_owned());
					info.pubkey_hash = Some(wp.program().into());
				} else if wp.program().len() == 32 {
					info.type_ = Some("p2wsh".to_owned());
					info.script_hash = Some(wp.program().into());
				} else {
					info.type_ = Some("invalid-witness-program".to_owned());
				}
			} else {
				info.type_ = Some("unknown-witness-program-version".to_owned());
			}
		}
	}
	if matches.is_present("yaml") {
		serde_yaml::to_writer(::std::io::stdout(), &info).unwrap();
	} else {
		serde_json::to_writer_pretty(::std::io::stdout(), &info).unwrap();
	}
}
