use std::{cmp, io};
use std::borrow::Cow;
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::cmd;

#[derive(PartialEq, PartialOrd, Eq, Ord)]
pub enum CommandInfo {
	BuiltIn {
		name: String,
	},
	External {
		name: String,
		path: PathBuf,
	},
}

impl CommandInfo {
	pub fn name(&self) -> String {
		match self {
			CommandInfo::BuiltIn {
				name,
			} => name.to_string(),
			CommandInfo::External {
				name,
				..
			} => name.to_string(),
		}
	}
}

/// Get the named argument from the CLI arguments or try read from stdin if not provided.
pub fn arg_or_stdin<'a>(matches: &'a clap::ArgMatches<'a>, arg: &str) -> Cow<'a, str> {
	if let Some(s) = matches.value_of(arg) {
		s.into()
	} else {
		// Read from stdin.
		let mut input = Vec::new();
		let stdin = io::stdin();
		let mut stdin_lock = stdin.lock();
		let _ = stdin_lock.read_to_end(&mut input);
		while stdin_lock.read_to_end(&mut input).unwrap_or(0) > 0 {}
		if input.is_empty() {
			panic!("no '{}' argument given", arg);
		}
		String::from_utf8(input).expect(&format!("invalid utf8 on stdin for '{}'", arg))
			.trim().to_owned().into()
	}
}

/// Return all directories in which to search for external executables.
pub fn search_directories() -> Vec<PathBuf> {
	let mut dirs = Vec::new();
	if let Some(val) = env::var_os("PATH") {
		dirs.extend(env::split_paths(&val));
	}
	dirs
}

#[cfg(unix)]
pub fn is_executable<P: AsRef<Path>>(path: P) -> bool {
	use std::os::unix::prelude::*;
	fs::metadata(path)
		.map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
		.unwrap_or(false)
}
#[cfg(windows)]
pub fn is_executable<P: AsRef<Path>>(path: P) -> bool {
	fs::metadata(path).map(|metadata| metadata.is_file()).unwrap_or(false)
}

/// List all runnable commands
pub fn list_commands() -> BTreeSet<CommandInfo> {
	let prefix = "hal-";
	let suffix = env::consts::EXE_SUFFIX;
	let mut commands = BTreeSet::new();

	for cmd in cmd::subcommands() {
		commands.insert(CommandInfo::BuiltIn {
			name: cmd.get_name().to_string(),
		});
	}

	for dir in search_directories() {
		let entries = match fs::read_dir(dir) {
			Ok(entries) => entries,
			_ => continue,
		};
		for entry in entries.filter_map(|e| e.ok()) {
			let path = entry.path();
			let filename = match path.file_name().and_then(|s| s.to_str()) {
				Some(filename) => filename,
				_ => continue,
			};
			if !filename.starts_with(prefix) || !filename.ends_with(suffix) {
				continue;
			}
			if is_executable(entry.path()) {
				let end = filename.len() - suffix.len();
				commands.insert(CommandInfo::External {
					name: filename[prefix.len()..end].to_string(),
					path: path.clone(),
				});
			}
		}
	}

	commands
}

pub fn lev_distance(me: &str, t: &str) -> usize {
	if me.is_empty() {
		return t.chars().count();
	}
	if t.is_empty() {
		return me.chars().count();
	}

	let mut dcol = (0..=t.len()).collect::<Vec<_>>();
	let mut t_last = 0;

	for (i, sc) in me.chars().enumerate() {
		let mut current = i;
		dcol[0] = current + 1;

		for (j, tc) in t.chars().enumerate() {
			let next = dcol[j + 1];

			if sc == tc {
				dcol[j + 1] = current;
			} else {
				dcol[j + 1] = cmp::min(current, next);
				dcol[j + 1] = cmp::min(dcol[j + 1], dcol[j]) + 1;
			}

			current = next;
			t_last = j;
		}
	}

	dcol[t_last + 1]
}

pub fn find_closest(cmd: &str) -> Option<String> {
	let cmds = list_commands();
	// Only consider candidates with a lev_distance of 3 or less so we don't
	// suggest out-of-the-blue options.
	cmds.into_iter()
		.map(|c| c.name())
		.map(|c| (lev_distance(&c, cmd), c))
		.filter(|&(d, _)| d < 4)
		.min_by_key(|a| a.0)
		.map(|slot| slot.1)
}

#[test]
fn test_lev_distance() {
	use std::char::{from_u32, MAX};
	// Test bytelength agnosticity
	for c in (0u32..MAX as u32).filter_map(from_u32).map(|i| i.to_string()) {
		assert_eq!(lev_distance(&c, &c), 0);
	}

	let a = "\nMäry häd ä little lämb\n\nLittle lämb\n";
	let b = "\nMary häd ä little lämb\n\nLittle lämb\n";
	let c = "Mary häd ä little lämb\n\nLittle lämb\n";
	assert_eq!(lev_distance(a, b), 1);
	assert_eq!(lev_distance(b, a), 1);
	assert_eq!(lev_distance(a, c), 2);
	assert_eq!(lev_distance(c, a), 2);
	assert_eq!(lev_distance(b, c), 1);
	assert_eq!(lev_distance(c, b), 1);
}
