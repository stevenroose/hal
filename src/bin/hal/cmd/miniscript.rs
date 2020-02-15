use clap;
use miniscript::{policy, MiniscriptKey};
use hal::miniscript::{PolicyInfo, PolicyKeyType};

use cmd;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	cmd::subcommand_group("miniscript", "work with miniscript (alias: ms)")
		.alias("ms")
		.subcommand(cmd_policy())
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	match matches.subcommand() {
		("policy", Some(ref m)) => exec_policy(&m),
		(_, _) => unreachable!("clap prints help"),
	};
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
	key_type: PolicyKeyType,
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
	if let Ok(info) = get_policy_info::<bitcoin::PublicKey>(policy_str, PolicyKeyType::PublicKey) {
		cmd::print_output(matches, &info)
	} else {
		// Then try with strings.
		match get_policy_info::<String>(policy_str, PolicyKeyType::String) {
			Ok(info) => cmd::print_output(matches, &info),
			Err(e) => panic!("Invalid policy: {}", e),
		}
	}
}
