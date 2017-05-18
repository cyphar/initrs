/*
 * initrs: simple init for containers
 * Copyright (C) 2017 SUSE LLC.
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
use std::io::Error;
use std::process::Command;
use std::os::unix::process::CommandExt;
use std::os::unix::io::AsRawFd;

extern crate libc;
use libc::pid_t;

extern crate nix;
use nix::{Errno, c_int};
use nix::unistd;
use nix::sys::wait::*;
use nix::sys::signal::*;
use nix::sys::signalfd::*;

#[macro_use]
extern crate clap;
use clap::{App, Arg, AppSettings};

/// Reaps all zombies that are children of initrs, returning the list of pids
/// that were reaped. If there are no children left alive or no children were
/// reaped, no error is returned. Unknown status codes from waitpid(2) are
/// logged and ignored.
fn reap_zombies() -> Result<Vec<pid_t>, Error> {
    let mut pids = Vec::new();
    loop {
        match waitpid(-1, Some(WNOHANG)) {
            // Did anything die?
            Ok(WaitStatus::Exited(cpid, _)) |
            Ok(WaitStatus::Signaled(cpid, _, _)) => {
                println!("[*] Child process exited: {}", cpid);
                pids.push(cpid);
            }

            // No children left or none of them have died.
            // TODO: ECHILD should cause us to quit.
            Ok(WaitStatus::StillAlive) |
            Err(nix::Error::Sys(Errno::ECHILD)) => break,

            // Error conditions.
            status @ Ok(_) => println!("[?] Unknown status: {:?}", status),
            Err(err) => return Err(Error::from(err)),
        };
    }
    return Ok(pids);
}

/// Forward the given signal to the provided process.
fn forward_signal(pid: pid_t, sig: Signal) -> Result<(), Error> {
    kill(pid, sig)?;

    println!("[+] Forwarded {:?} to {}", sig, pid);
    return Ok(());
}

/// Places a process in the foreground (this function should be called in the
/// context of a Command::before_exec closure), making it the leader of a new
/// process group that is set to be the foreground process group in its session
/// with the current pty.
fn make_foreground() -> Result<(), Error> {
    // Create a new process group.
    unistd::setpgid(0, 0)?;
    let pgid = unistd::getpgid(None)?;

    // Open /dev/tty, to avoid issues of std{in,out,err} being duped.
    let tty = File::open("/dev/tty")?;

    // We have to block SIGTTOU here otherwise we will get stopped if we are in
    // a background process group.
    let mut sigmask = SigSet::all();
    sigmask.add(Signal::SIGTTOU);
    sigmask.thread_block()?;

    // Set ourselves to be the foreground process group in our session.
    return match unistd::tcsetpgrp(tty.as_raw_fd(), pgid) {
               // We have succeeded in being the foreground process.
               Ok(_) => Ok(()),

               // ENOTTY [no tty] and ENXIO [lx zones] can happen in "normal" usage,
               // which indicate that we aren't in the foreground.
               // TODO: Should we undo the setpgid(0, 0) here?
               err @ Err(nix::Error::Sys(Errno::ENOTTY)) |
               err @ Err(nix::Error::Sys(Errno::ENXIO)) => {
                   println!("[*] Failed to set process in foreground: {:?}", err);
                   Ok(())
               }

               Err(err) => Err(Error::from(err)),
           };
}

fn main() {
    // We need to store the initial signal mask first, which we will restore
    // before execing the user process (signalfd requires us to block all
    // signals we are masking but this would be inherited by our child).
    let init_sigmask = SigSet::thread_get_mask().expect("could not get main thread sigmask");

    // Block all signals so we can use signalfd. Note that while it would be
    // great for us to just set SIGCHLD to SIG_IGN (that way zombies will be
    // auto-reaped by the kernel for us, as guaranteed by POSIX-2001 and SUS)
    // this way we can more easily handle the child we are forwarding our
    // signals to dying.
    let sigmask = SigSet::all();
    sigmask.thread_block().expect("could not block all signals");
    let mut sfd = SignalFd::new(&sigmask).expect("could not create signalfd for all signals");

    // Parse options.
    let options = App::new("initrs")
                      .setting(AppSettings::TrailingVarArg)
                      .author("Aleksa Sarai <asarai@suse.de>")
                      .version(crate_version!())
                      .about("Simple init for containers.")
                      // Represents the actual command to be run.
                      .arg(Arg::with_name("command")
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

    // Loop, reading all signals we recieved to figure out
    let pid = child.id() as pid_t;
    loop {
        // TODO: Handle errors in a more sane way. :wink:
        let siginfo = sfd.read_signal()
            .expect("could not read signal")
            .expect("no signal was read");
        let signum = Signal::from_c_int(siginfo.ssi_signo as c_int)
            .expect("could not parse ssi_signo as Signal");

        let result = match signum {
            Signal::SIGCHLD => reap_zombies().and_then(|pids| Ok(pids.contains(&pid))),
            _ => forward_signal(pid, signum).map(|_| false),
        };

        match result {
            Ok(true) => break,
            Ok(false) => continue,
            Err(err) => println!("[!] Hit an error in handling {:?}: {}", signum, err),
        };
    }

    println!("[+] Child has exited, we are done.");
}
