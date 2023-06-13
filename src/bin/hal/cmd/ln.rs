use clap;
use lightning_invoice::Invoice;

use crate::prelude::*;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("ln", "everything Lightning").subcommand(
		cmd::subcommand_group("invoice", "handle Lightning invoices")
			.subcommand(cmd_invoice_decode()),
	)
}

pub fn execute<'a>(args: &clap::ArgMatches<'a>) {
	match args.subcommand() {
		("invoice", Some(ref args)) => match args.subcommand() {
			("decode", Some(ref m)) => exec_invoice_decode(&m),
			(_, _) => unreachable!("clap prints help"),
		},
		(_, _) => unreachable!("clap prints help"),
	};
}

fn cmd_invoice_decode<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("decode", "decode Lightning invoices")
		.args(&args::opts_networks())
		.args(&[args::opt_yaml(), args::arg("invoice", "the invoice in bech32").required(false)])
}

fn exec_invoice_decode<'a>(args: &clap::ArgMatches<'a>) {
	::lightning_invoice::check_platform();

	let invoice_str = util::arg_or_stdin(args, "invoice");
	let invoice: Invoice = invoice_str.as_ref().parse().expect("invalid invoice encoding");

	let info = hal::GetInfo::get_info(&invoice, args.network());
	args.print_output(&info)
}
