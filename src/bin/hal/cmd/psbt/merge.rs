use std::fs::File;
use std::io::Write;

use bitcoin::consensus::deserialize;
use bitcoin::consensus::serialize;
use bitcoin::util::psbt;

use clap;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	clap::SubCommand::with_name("merge")
		.about("merge multiple PSBT files into one")
		.arg(
			clap::Arg::with_name("psbts")
				.help("PSBTs to merge; can be files or hex")
				.takes_value(true)
				.multiple(true)
				.required(true),
		)
		.arg(
			clap::Arg::with_name("output")
				.long("output")
				.short("o")
				.help("where to save the merged PSBT output")
				.takes_value(true)
				.required(false),
		)
		.arg(
			clap::Arg::with_name("raw-stdout")
				.long("raw")
				.short("r")
				.help("output the raw bytes of the result to stdout")
				.required(false),
		)
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	let mut parts = matches.values_of("psbts").unwrap().map(|f| {
		let (raw, _) = super::file_or_raw(&f);
		let psbt: psbt::PartiallySignedTransaction =
			deserialize(&raw).expect("invalid PSBT format");
		psbt
	});

	let mut merged = parts.next().unwrap();
	for (idx, part) in parts.enumerate() {
		if part.global.unsigned_tx != merged.global.unsigned_tx {
			panic!("PSBTs are not compatible");
		}

		merged.merge(part).expect(&format!("error merging PSBT #{}", idx));
	}

	let merged_raw = serialize(&merged);
	if let Some(path) = matches.value_of("output") {
		let mut file = File::create(&path).expect("failed to open output file");
		file.write_all(&merged_raw).expect("error writing output file");
	} else if matches.is_present("raw-stdout") {
		::std::io::stdout().write_all(&merged_raw).unwrap();
	} else {
		print!("{}", base64::encode(&merged_raw));
	}
}
