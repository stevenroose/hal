use std::fs::File;
use std::io::Read;

use base64;
use clap;
use hex;

mod create;
mod decode;
mod edit;
mod merge;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	clap::SubCommand::with_name("psbt")
		.about("partially signed Bitcoin transactions")
		.setting(clap::AppSettings::SubcommandRequiredElseHelp)
		.setting(clap::AppSettings::DisableHelpSubcommand)
		.subcommand(create::subcommand())
		.subcommand(decode::subcommand())
		.subcommand(edit::subcommand())
		.subcommand(merge::subcommand())
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	match matches.subcommand() {
		("create", Some(ref m)) => create::execute(&m),
		("decode", Some(ref m)) => decode::execute(&m),
		("edit", Some(ref m)) => edit::execute(&m),
		("merge", Some(ref m)) => merge::execute(&m),
		(c, _) => println!("command {} unknown", c),
	};
}

pub enum PsbtSource {
	Base64,
	Hex,
	File,
}

/// Tries to decode the string as hex and base64, if it works, returns the bytes.
/// If not, tries to open a filename with the given string as relative path, if it works, returns
/// the content bytes.
/// Also returns an enum value indicating which source worked.
pub fn file_or_raw(flag: &str) -> (Vec<u8>, PsbtSource) {
	if let Ok(raw) = hex::decode(&flag) {
		(raw, PsbtSource::Hex)
	} else if let Ok(raw) = base64::decode(&flag) {
		(raw, PsbtSource::Base64)
	} else if let Ok(mut file) = File::open(&flag) {
		let mut buf = Vec::new();
		file.read_to_end(&mut buf).expect("error reading file");
		(buf, PsbtSource::File)
	} else {
		panic!("Can't load PSBT: invalid hex, base64 or unknown file");
	}
}
