use clap;
use lightning_invoice::Invoice;

use cmd;
use hal;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("decode", "decode Lightning invoices")
		.args(&cmd::opts_networks())
		.args(&[cmd::opt_yaml(), cmd::arg("invoice", "the invoice in bech32").required(true)])
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	::lightning_invoice::check_platform();

	let invoice_str = matches.value_of("invoice").expect("no invoice provided");
	let invoice: Invoice = invoice_str.parse().expect("invalid invoice encoding");

	let info = hal::GetInfo::get_info(&invoice, cmd::network(matches));
	cmd::print_output(matches, &info)
}
