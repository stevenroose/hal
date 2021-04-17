// This file is copied from the Cargo project and adapted only to remove
// unnecessary parts.
// Cargo is primarily distributed under the terms of both the MIT license and
// the Apache License (Version 2.0).
#![allow(unused)]

use std::collections::HashMap;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::Path;
use std::process::Command;

use jobserver::Client;
use shell_escape::escape;

/// A builder object for an external process, similar to `std::process::Command`.
#[derive(Clone, Debug)]
pub struct ProcessBuilder {
	/// The program to execute.
	program: OsString,
	/// A list of arguments to pass to the program.
	args: Vec<OsString>,
	/// Any environment variables that should be set for the program.
	env: HashMap<String, Option<OsString>>,
	/// The directory to run the program from.
	cwd: Option<OsString>,
	/// The `make` jobserver. See the [jobserver crate][jobserver_docs] for
	/// more information.
	///
	/// [jobserver_docs]: https://docs.rs/jobserver/0.1.6/jobserver/
	jobserver: Option<Client>,
	/// `true` to include environment variable in display.
	display_env_vars: bool,
}

impl fmt::Display for ProcessBuilder {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "`")?;

		if self.display_env_vars {
			for (key, val) in self.env.iter() {
				if let Some(val) = val {
					let val = escape(val.to_string_lossy());
					if cfg!(windows) {
						write!(f, "set {}={}&& ", key, val)?;
					} else {
						write!(f, "{}={} ", key, val)?;
					}
				}
			}
		}

		write!(f, "{}", self.program.to_string_lossy())?;

		for arg in &self.args {
			write!(f, " {}", escape(arg.to_string_lossy()))?;
		}

		write!(f, "`")
	}
}

impl ProcessBuilder {
	/// (chainable) Sets the executable for the process.
	pub fn program<T: AsRef<OsStr>>(&mut self, program: T) -> &mut ProcessBuilder {
		self.program = program.as_ref().to_os_string();
		self
	}

	/// (chainable) Adds `arg` to the args list.
	pub fn arg<T: AsRef<OsStr>>(&mut self, arg: T) -> &mut ProcessBuilder {
		self.args.push(arg.as_ref().to_os_string());
		self
	}

	/// (chainable) Adds multiple `args` to the args list.
	pub fn args<T: AsRef<OsStr>>(&mut self, args: &[T]) -> &mut ProcessBuilder {
		self.args.extend(args.iter().map(|t| t.as_ref().to_os_string()));
		self
	}

	/// (chainable) Replaces the args list with the given `args`.
	pub fn args_replace<T: AsRef<OsStr>>(&mut self, args: &[T]) -> &mut ProcessBuilder {
		self.args = args.iter().map(|t| t.as_ref().to_os_string()).collect();
		self
	}

	/// (chainable) Sets the current working directory of the process.
	pub fn cwd<T: AsRef<OsStr>>(&mut self, path: T) -> &mut ProcessBuilder {
		self.cwd = Some(path.as_ref().to_os_string());
		self
	}

	/// (chainable) Sets an environment variable for the process.
	pub fn env<T: AsRef<OsStr>>(&mut self, key: &str, val: T) -> &mut ProcessBuilder {
		self.env.insert(key.to_string(), Some(val.as_ref().to_os_string()));
		self
	}

	/// (chainable) Unsets an environment variable for the process.
	pub fn env_remove(&mut self, key: &str) -> &mut ProcessBuilder {
		self.env.insert(key.to_string(), None);
		self
	}

	/// Gets the executable name.
	pub fn get_program(&self) -> &OsString {
		&self.program
	}

	/// Gets the program arguments.
	pub fn get_args(&self) -> &[OsString] {
		&self.args
	}

	/// Gets the current working directory for the process.
	pub fn get_cwd(&self) -> Option<&Path> {
		self.cwd.as_ref().map(Path::new)
	}

	/// Gets an environment variable as the process will see it (will inherit from environment
	/// unless explicitally unset).
	pub fn get_env(&self, var: &str) -> Option<OsString> {
		self.env.get(var).cloned().or_else(|| Some(env::var_os(var))).and_then(|s| s)
	}

	/// Gets all environment variables explicitly set or unset for the process (not inherited
	/// vars).
	pub fn get_envs(&self) -> &HashMap<String, Option<OsString>> {
		&self.env
	}

	/// Sets the `make` jobserver. See the [jobserver crate][jobserver_docs] for
	/// more information.
	///
	/// [jobserver_docs]: https://docs.rs/jobserver/0.1.6/jobserver/
	pub fn inherit_jobserver(&mut self, jobserver: &Client) -> &mut Self {
		self.jobserver = Some(jobserver.clone());
		self
	}

	/// Enables environment variable display.
	pub fn display_env_vars(&mut self) -> &mut Self {
		self.display_env_vars = true;
		self
	}

	/// Runs the process, waiting for completion, and mapping non-success exit codes to an error.
	pub fn exec(&self) {
		let mut command = self.build_command();
		let exit = command.status().expect(&format!("could not execute process {}", self));

		if !exit.success() {
			panic!("process didn't exit successfully: {}", self);
		}
	}

	/// Replaces the current process with the target process.
	///
	/// On Unix, this executes the process using the Unix syscall `execvp`, which will block
	/// this process, and will only return if there is an error.
	///
	/// On Windows this isn't technically possible. Instead we emulate it to the best of our
	/// ability. One aspect we fix here is that we specify a handler for the Ctrl-C handler.
	/// In doing so (and by effectively ignoring it) we should emulate proxying Ctrl-C
	/// handling to the application at hand, which will either terminate or handle it itself.
	/// According to Microsoft's documentation at
	/// <https://docs.microsoft.com/en-us/windows/console/ctrl-c-and-ctrl-break-signals>.
	/// the Ctrl-C signal is sent to all processes attached to a terminal, which should
	/// include our child process. If the child terminates then we'll reap them in Cargo
	/// pretty quickly, and if the child handles the signal then we won't terminate
	/// (and we shouldn't!) until the process itself later exits.
	pub fn exec_replace(&self) {
		imp::exec_replace(self)
	}

	/// Executes the process, returning the stdio output, or an error if non-zero exit status.
	pub fn exec_with_output(&self) {
		let mut command = self.build_command();

		let output = command.output().expect(&format!("could not execute process {}", self));

		if !output.status.success() {
			panic!("process didn't exit successfully: {}", self);
		}
	}

	/// Converts `ProcessBuilder` into a `std::process::Command`, and handles the jobserver, if
	/// present.
	pub fn build_command(&self) -> Command {
		let mut command = Command::new(&self.program);
		if let Some(cwd) = self.get_cwd() {
			command.current_dir(cwd);
		}
		for arg in &self.args {
			command.arg(arg);
		}
		for (k, v) in &self.env {
			match *v {
				Some(ref v) => {
					command.env(k, v);
				}
				None => {
					command.env_remove(k);
				}
			}
		}
		if let Some(ref c) = self.jobserver {
			c.configure(&mut command);
		}
		command
	}
}

/// A helper function to create a `ProcessBuilder`.
pub fn process<T: AsRef<OsStr>>(cmd: T) -> ProcessBuilder {
	ProcessBuilder {
		program: cmd.as_ref().to_os_string(),
		args: Vec::new(),
		cwd: None,
		env: HashMap::new(),
		jobserver: None,
		display_env_vars: false,
	}
}

#[cfg(unix)]
mod imp {
	use super::ProcessBuilder;
	use std::os::unix::process::CommandExt;

	pub fn exec_replace(process_builder: &ProcessBuilder) {
		let mut command = process_builder.build_command();
		command.exec();
	}
}

//TODO(stevenroose) test this
#[cfg(windows)]
mod imp {
	use crate::util::{process_error, ProcessBuilder};
	use crate::CargoResult;
	use winapi::shared::minwindef::{BOOL, DWORD, FALSE, TRUE};
	use winapi::um::consoleapi::SetConsoleCtrlHandler;

	unsafe extern "system" fn ctrlc_handler(_: DWORD) -> BOOL {
		// Do nothing; let the child process handle it.
		TRUE
	}

	pub fn exec_replace(process_builder: &ProcessBuilder) -> CargoResult<()> {
		unsafe {
			if SetConsoleCtrlHandler(Some(ctrlc_handler), TRUE) == FALSE {
				return Err(process_error("Could not set Ctrl-C handler.", None, None).into());
			}
		}

		// Just execute the process as normal.
		process_builder.exec()
	}
}
