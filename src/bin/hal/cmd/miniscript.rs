use clap;
use hal::miniscript::{DescriptorInfo, MiniscriptInfo, MiniscriptKeyType, PolicyInfo};
use miniscript::descriptor::Descriptor;
use miniscript::miniscript::Miniscript;
use miniscript::{policy, DummyKey, DummyKeyHash, MiniscriptKey};

use cmd;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("miniscript", "work with miniscript (alias: ms)")
		.alias("ms")
		.subcommand(cmd_descriptor())
		.subcommand(cmd_inspect())
		.subcommand(cmd_policy())
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	match matches.subcommand() {
		("descriptor", Some(ref m)) => exec_descriptor(&m),
		("inspect", Some(ref m)) => exec_inspect(&m),
		("policy", Some(ref m)) => exec_policy(&m),
		(_, _) => unreachable!("clap prints help"),
	};
}

fn cmd_descriptor<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("descriptor", "get information about an output descriptor")
		.arg(cmd::opt_yaml())
		.args(&[cmd::arg("descriptor", "the output descriptor to inspect").required(true)])
}

fn exec_descriptor<'a>(matches: &clap::ArgMatches<'a>) {
	let desc_str = matches.value_of("descriptor").expect("no descriptor argument given");
	let network = cmd::network(matches);

	let info = desc_str
		.parse::<Descriptor<bitcoin::PublicKey>>()
		.map(|desc| DescriptorInfo {
			key_type: MiniscriptKeyType::PublicKey,
			address: desc.address(network).map(|a| a.to_string()),
			script_pubkey: Some(desc.script_pubkey().into_bytes().into()),
			unsigned_script_sig: Some(desc.unsigned_script_sig().into_bytes().into()),
			witness_script: Some(desc.witness_script().into_bytes().into()),
			max_satisfaction_weight: desc.max_satisfaction_weight(),
			policy: policy::Liftable::lift(&desc).to_string(),
		})
		.or_else(|e| {
			debug!("Can't parse descriptor with public keys: {}", e);
			// Then try with strings.
			desc_str.parse::<Descriptor<String>>().map(|desc| {
				let dummy = {
					let res: Result<_, ()> =
						desc.translate_pk(|_| Ok(DummyKey), |_| Ok(DummyKeyHash));
					res.unwrap()
				};
				DescriptorInfo {
					key_type: MiniscriptKeyType::String,
					address: None,
					script_pubkey: None,
					unsigned_script_sig: None,
					witness_script: None,
					max_satisfaction_weight: dummy.max_satisfaction_weight(),
					policy: policy::Liftable::lift(&desc).to_string(),
				}
			})
		})
		.expect("invalid miniscript");
	cmd::print_output(matches, &info);
}

fn cmd_inspect<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("inspect", "inspect miniscripts").arg(cmd::opt_yaml()).args(&[cmd::arg(
		"miniscript",
		"the miniscript to inspect",
	)
	.required(true)])
}

fn exec_inspect<'a>(matches: &clap::ArgMatches<'a>) {
	let miniscript_str = matches.value_of("miniscript").expect("no miniscript argument given");

	// First try with pubkeys.
	let info = miniscript_str
		.parse::<Miniscript<bitcoin::PublicKey>>()
		.map(|ms| MiniscriptInfo {
			key_type: MiniscriptKeyType::PublicKey,
			script_size: ms.script_size(),
			max_satisfaction_witness_elements: ms.max_satisfaction_witness_elements(),
			max_satisfaction_size_segwit: ms.max_satisfaction_size(2),
			max_satisfaction_size_non_segwit: ms.max_satisfaction_size(1),
			script: Some(ms.encode().into_bytes().into()),
			policy: policy::Liftable::lift(&ms).to_string(),
		})
		.or_else(|e| {
			debug!("Can't parse miniscript with public keys: {}", e);
			// Then try with strings.
			miniscript_str.parse::<Miniscript<String>>().map(|ms| {
				let dummy = {
					let res: Result<_, ()> =
						ms.translate_pk(&mut |_| Ok(DummyKey), &mut |_| Ok(DummyKeyHash));
					res.unwrap()
				};
				MiniscriptInfo {
					key_type: MiniscriptKeyType::String,
					script_size: dummy.script_size(),
					max_satisfaction_witness_elements: dummy.max_satisfaction_witness_elements(),
					max_satisfaction_size_segwit: dummy.max_satisfaction_size(2),
					max_satisfaction_size_non_segwit: dummy.max_satisfaction_size(1),
					script: None,
					policy: policy::Liftable::lift(&ms).to_string(),
				}
			})
		})
		.expect("invalid miniscript");
	cmd::print_output(matches, &info);
}

fn cmd_policy<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand("policy", "inspect policies").arg(cmd::opt_yaml()).args(&[cmd::arg(
		"policy",
		"the miniscript policy to inspect",
	)
	.required(true)])
}

fn get_policy_info<Pk: MiniscriptKey>(
	policy_str: &str,
	key_type: MiniscriptKeyType,
) -> Result<PolicyInfo, miniscript::Error>
where
	<<Pk as miniscript::MiniscriptKey>::Hash as ::std::str::FromStr>::Err: ::std::fmt::Display,
	<Pk as ::std::str::FromStr>::Err: ::std::fmt::Display,
{
	let concrete_pol: Option<policy::Concrete<Pk>> = policy_str.parse().ok();
	let policy = match concrete_pol {
		Some(ref concrete) => policy::Liftable::lift(concrete),
		None => policy_str.parse()?,
	};
	Ok(PolicyInfo {
		is_concrete: concrete_pol.is_some(),
		key_type: key_type,
		is_trivial: policy.is_trivial(),
		is_unsatisfiable: policy.is_unsatisfiable(),
		relative_timelocks: policy.relative_timelocks(),
		n_keys: policy.n_keys(),
		minimum_n_keys: policy.minimum_n_keys(),
		sorted: policy.clone().sorted().to_string(),
		normalized: policy.clone().normalized().to_string(),
		miniscript: concrete_pol.and_then(|p| match policy::compiler::best_compilation(&p) {
			Ok(ms) => Some(ms.to_string()),
			Err(e) => {
				info!("Compiler error: {}", e);
				None
			}
		}),
	})
}

fn exec_policy<'a>(matches: &clap::ArgMatches<'a>) {
	let policy_str = matches.value_of("policy").expect("no policy argument given");

	// First try a concrete policy with pubkeys.
	if let Ok(info) =
		get_policy_info::<bitcoin::PublicKey>(policy_str, MiniscriptKeyType::PublicKey)
	{
		cmd::print_output(matches, &info)
	} else {
		// Then try with strings.
		match get_policy_info::<String>(policy_str, MiniscriptKeyType::String) {
			Ok(info) => cmd::print_output(matches, &info),
			Err(e) => panic!("Invalid policy: {}", e),
		}
	}
}
