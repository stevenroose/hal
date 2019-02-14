use clap;
use lightning_invoice::Invoice;

use cmd;
use hal;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	clap::SubCommand::with_name("decode")
		.about("decode Lightning invoices")
		.arg(cmd::arg_testnet())
		.arg(cmd::arg_regtest())
		.arg(cmd::arg_yaml())
		.arg(
			clap::Arg::with_name("invoice")
				.help("the invoice in bech32")
				.takes_value(true)
				.required(true),
		)
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	::lightning_invoice::check_platform();

	let invoice_str = matches.value_of("invoice").expect("no invoice provided");
	let invoice: Invoice = invoice_str.parse().expect("invalid invoice encoding");

	let info = hal::GetInfo::get_info(&invoice, cmd::network(matches));
	cmd::print_output(matches, &info)
}
