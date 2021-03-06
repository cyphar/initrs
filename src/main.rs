/*
 * initrs: simple init for containers
 * Copyright (C) 2017, 2018 SUSE LLC.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

// I don't like ruby-like returns.
#![cfg_attr(feature="cargo-clippy", allow(needless_return))]

//! initrs is a minimal container init that implements signal forwarding, zombie
//! reaping and other similar features you would expect from a simple container
//! init. It only runs a single program as the "main program" which is placed in
//! a foreground process group on the controlling TTY. At the moment it does not
//! nicely handle running as a non PID-1 process.
//!
//! ```notrust
//! $ initrs --help
//! initrs 0.0.0
//! Aleksa Sarai <asarai@suse.de>
//! Simple init for containers.
//!
//! USAGE:
//!   initrs <command>...
//!
//! FLAGS:
//!   -h, --help       Prints help information
//!   -V, --version    Prints version information
//!
//! ARGS:
//!   <command>...
//! ```

use std::fs::File;
use std::io::{Error, ErrorKind};
use std::process::Command;
use std::os::unix::process::CommandExt;
use std::os::unix::io::AsRawFd;

extern crate libc;
use libc::pid_t;

extern crate nix;
use nix::{Errno, c_int};
use nix::unistd;
use nix::sys::wait;
use nix::sys::signal;
use nix::sys::signalfd;

#[macro_use]
extern crate log;
extern crate env_logger;

#[macro_use]
extern crate clap;

/// Reaps all zombies that are children of initrs, returning the list of pids
/// that were reaped. If there are no children left alive or no children were
/// reaped, no error is returned. Unknown status codes from waitpid(2) are
/// logged and ignored.
fn reap_zombies() -> Result<Vec<pid_t>, Error> {
    let mut pids = Vec::new();
    loop {
        match wait::waitpid(-1, Some(wait::WNOHANG)) {
            // Did anything die?
            Ok(wait::WaitStatus::Exited(cpid, _)) |
            Ok(wait::WaitStatus::Signaled(cpid, _, _)) => {
                debug!("child process exited: {}", cpid);
                pids.push(cpid);
            }

            // No children left or none of them have died.
            // TODO: ECHILD really should cause us to quit (but doesn't currently), since
            //       if we get ECHILD we know that we have no children and thus will never get a
            //       SIGCHLD again. But this assumes we missed the SIGCHLD of the main process
            //       (which shouldn't be possible).
            Ok(wait::WaitStatus::StillAlive) |
            Err(nix::Error::Sys(Errno::ECHILD)) => break,

            // Error conditions.
            status @ Ok(_) => info!("saw unknown status: {:?}", status),
            Err(err) => return Err(Error::from(err)),
        };
    }
    return Ok(pids);
}

/// Forward the given signal to the provided process.
fn forward_signal(pid: pid_t, sig: signal::Signal) -> Result<(), Error> {
    signal::kill(pid, sig)?;

    debug!("forwarded {:?} to {}", sig, pid);
    return Ok(());
}

/// process_signals reads a signal from the given SignalFd and then handles it. If any child pids
/// were detected as having died, they are returned (an empty Vec means that no children died or
/// the signal wasn't SIGCHLD).
fn process_signals(pid1: pid_t, sfd: &mut signalfd::SignalFd) -> Result<Vec<pid_t>, Error> {
    let siginfo = sfd.read_signal()?.ok_or(Error::new(
        ErrorKind::Other,
        "no signals read",
    ))?;
    let signum = signal::Signal::from_c_int(siginfo.ssi_signo as c_int)?;

    match signum {
        signal::Signal::SIGCHLD => reap_zombies(),
        _ => forward_signal(pid1, signum).map(|_| Vec::new()),
    }
}

/// Places a process in the foreground (this function should be called in the
/// context of a `Command::before_exec` closure), making it the leader of a new
/// process group that is set to be the foreground process group in its session
/// with the current pty.
fn make_foreground() -> Result<(), Error> {
    // Create a new process group.
    unistd::setpgid(0, 0)?;
    let pgrp = unistd::getpgrp();

    // Open /dev/tty, to avoid issues of std{in,out,err} being duped.
    let tty = match File::open("/dev/tty") {
        Ok(tty) => tty,
        // We ignore errors opening. This means that there's no PTY set up.
        Err(err) => {
            info!("failed to open /dev/tty: {}", err);
            return Ok(());
        },
    };

    // We have to block SIGTTOU here otherwise we will get stopped if we are in
    // a background process group.
    let mut sigmask = signal::SigSet::empty();
    sigmask.add(signal::Signal::SIGTTOU);
    sigmask.thread_block()?;

    // Set ourselves to be the foreground process group in our session.
    return match unistd::tcsetpgrp(tty.as_raw_fd(), pgrp) {
        // We have succeeded in being the foreground process.
        Ok(_) => Ok(()),

        // ENOTTY [no tty] and ENXIO [lx zones] can happen in "normal" usage,
        // which indicate that we aren't in the foreground.
        // TODO: Should we undo the setpgid(0, 0) here?
        err @ Err(nix::Error::Sys(Errno::ENOTTY)) |
        err @ Err(nix::Error::Sys(Errno::ENXIO)) => {
            info!("failed to set process in foreground: {:?}", err);
            Ok(())
        }

        Err(err) => Err(Error::from(err)),
    };
}

fn main() {
    // Set up logging.
    let env = env_logger::Env::new().filter("INITRS_LOG")
                                    .write_style("INITRS_LOG_STYLE");
    env_logger::init_from_env(env);

    // We need to store the initial signal mask first, which we will restore
    // before execing the user process (signalfd requires us to block all
    // signals we are masking but this would be inherited by our child).
    let init_sigmask =
        signal::SigSet::thread_get_mask().expect("could not get main thread sigmask");

    // Block all signals so we can use signalfd. Note that while it would be
    // great for us to just set SIGCHLD to SIG_IGN (that way zombies will be
    // auto-reaped by the kernel for us, as guaranteed by POSIX-2001 and SUS)
    // this way we can more easily handle the child we are forwarding our
    // signals to dying.
    let sigmask = signal::SigSet::all();
    sigmask.thread_block().expect("could not block all signals");
    let mut sfd =
        signalfd::SignalFd::new(&sigmask).expect("could not create signalfd for all signals");

    // Parse options.
    let options = clap::App::new("initrs")
                            .setting(clap::AppSettings::TrailingVarArg)
                            .author("Aleksa Sarai <asarai@suse.de>")
                            .version(crate_version!())
                            .about("Simple init for containers.")
                            // Represents the actual command to be run.
                            .arg(clap::Arg::with_name("command")
                                           .required(true)
                                           .multiple(true))
                            .get_matches();

    // Get the arguments for the process to run.
    let args = options.values_of("command").unwrap().collect::<Vec<_>>();
    let (cmd, args) = args.as_slice().split_first().unwrap();

    // Spawn the child.
    let child = Command::new(cmd)
        .args(args)
        .before_exec(move || {
            make_foreground()?;
            init_sigmask.thread_set_mask()?;
            return Ok(());
        })
        .spawn()
        .expect("failed to start child process");

    // Loop, reading all signals we recieved to figure out what the correct response is (forward
    // all signals other than SIGCHLD which we react to by reaping the children). In addition all
    // errors are logged and ignored from here on out -- because we *must not exit* as we are pid1
    // and exiting will kill the container.
    let pid1 = child.id() as pid_t;
    debug!("spawned '{}' as pid1 with pid {}", cmd, pid1);
    loop {
        match process_signals(pid1, &mut sfd) {
            Err(err) => info!("unexpected error during signal handling: {}", err),
            Ok(pids) => {
                if pids.contains(&pid1) {
                    break;
                }
            }
        };
    }

    debug!("bailing: pid1 {} has exited", pid1);
}
