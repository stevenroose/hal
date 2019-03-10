use bitcoin::Address;
use bitcoin_hashes::Hash;
use clap;

use cmd;
use hal;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("inspect", "inspect addresses").args(&[
		cmd::opt_yaml(),
		cmd::opt("address", "the address").takes_value(true).required(true),
	])
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	let address_str = matches.value_of("address").expect("no address provided");
	let address: Address = address_str.parse().expect("invalid address format");
	let script_pk = address.script_pubkey();

	let mut info = hal::address::AddressInfo {
		network: address.network,
		script_pub_key: hal::tx::OutputScriptInfo {
			hex: Some(script_pk.to_bytes().into()),
			asm: Some(script_pk.asm()),
			address: None,
			type_: None,
		},
		type_: None,
		pubkey_hash: None,
		script_hash: None,
		witness_program_version: None,
	};

	use bitcoin::util::address::Payload;
	match address.payload {
		Payload::PubkeyHash(pkh) => {
			info.type_ = Some("p2pkh".to_owned());
			info.pubkey_hash = Some(pkh.into_inner()[..].into());
		}
		Payload::ScriptHash(ref sh) => {
			info.type_ = Some("p2sh".to_owned());
			info.script_hash = Some(sh.into_inner()[..].into());
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

	cmd::print_output(matches, &info)
}
