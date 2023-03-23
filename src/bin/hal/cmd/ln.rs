use clap;
use lightning_invoice::Invoice;

use crate::{cmd, util};

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("ln", "everything Lightning").subcommand(
		cmd::subcommand_group("invoice", "handle Lightning invoices")
			.subcommand(cmd_invoice_decode()),
	)
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	match matches.subcommand() {
		("invoice", Some(ref matches)) => match matches.subcommand() {
			("decode", Some(ref m)) => exec_invoice_decode(&m),
			(_, _) => unreachable!("clap prints help"),
		},
		(_, _) => unreachable!("clap prints help"),
	};
}

fn cmd_invoice_decode<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("decode", "decode Lightning invoices")
		.args(&cmd::opts_networks())
		.args(&[cmd::opt_yaml(), cmd::arg("invoice", "the invoice in bech32").required(false)])
}

fn exec_invoice_decode<'a>(matches: &clap::ArgMatches<'a>) {
	::lightning_invoice::check_platform();

	let invoice_str = util::arg_or_stdin(matches, "invoice");
	let invoice: Invoice = invoice_str.as_ref().parse().expect("invalid invoice encoding");

	let info = hal::GetInfo::get_info(&invoice, cmd::network(matches));
	cmd::print_output(matches, &info)
}
