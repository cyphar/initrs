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

use std::io::Error;
use std::process::Command;
use std::os::unix::process::CommandExt;

extern crate libc;
use libc::pid_t;

extern crate nix;
use nix::c_int;
use nix::Errno;
use nix::sys::wait::*;
use nix::sys::signal::*;
use nix::sys::signalfd::*;

#[macro_use]
extern crate clap;
use clap::{App, Arg, AppSettings};

fn reap_zombies() -> Result<Vec<pid_t>, Error> {
    let mut pids = Vec::new();
    loop {
        match waitpid(-1, Some(WNOHANG)) {
            // Did anything die?
            Ok(WaitStatus::Exited(cpid, _)) |
            Ok(WaitStatus::Signaled(cpid, _, _)) => {
                println!("[*] Child process exited: {}", cpid);
                pids.push(cpid);
            },
            // No children left or none of them have died.
            // TODO: ECHILD should cause us to quit.
            Ok(WaitStatus::StillAlive) |
            Err(nix::Error::Sys(Errno::ECHILD)) => break,
            // Error conditions.
            status @ Ok(_) => println!("[?] Unknown status: {:?}", status),
            Err(err)       => return Err(Error::from(err)),
        };
    }
    return Ok(pids);
}

fn forward_signal(pid: &pid_t, sig: Signal) -> Result<bool, Error> {
    return match kill(*pid, sig) {
        Ok(_) => {
            println!("[+] Forwarded {:?} to {}", sig, pid);
            Ok(false)
        },
        Err(err) => Err(Error::from(err)),
    };
}

fn main() {
    // We need to store the initial signal mask first, which we will restore
    // before execing the user process (signalfd requires us to block all
    // signals we are masking but this would be inherited by our child).
    let init_sigmask = SigSet::thread_get_mask().unwrap();

    // Block all signals so we can use signalfd. Note that while it would be
    // great for us to just set SIGCHLD to SIG_IGN (that way zombies will be
    // auto-reaped by the kernel for us, as guaranteed by POSIX-2001 and SUS)
    // this way we can more easily handle the child we are forwarding our
    // signals to dying.
    let sigmask = SigSet::all();
    sigmask.thread_block().unwrap();
    let mut sfd = SignalFd::new(&sigmask).unwrap();

    // Parse options.
    let options = App::new("initrs")
                      .setting(AppSettings::TrailingVarArg)
                      .author("Aleksa Sarai <asarai@suse.de>")
                      .version(crate_version!())
                      .about("Simple init for containers.")
                      // Represents the actual command to be run.
                      .arg(Arg::with_name("command")
                               .multiple(true))
                      .get_matches();

    // Get the arguments for the process to run.
    let args = options.values_of("command").unwrap()
                      .collect::<Vec<_>>();
    let (cmd, args) = args.as_slice()
                          .split_first().unwrap();

    // Spawn the child.
    let child = Command::new(cmd)
                        .args(args)
                        .before_exec(move || match init_sigmask.thread_set_mask() {
                            Ok(_) => Ok(()),
                            Err(err) => Err(Error::from(err)),
                        })
                        .spawn().expect("failed to start child process");

    // Loop, reading all signals we recieved to figure out
    let pid = child.id() as pid_t;
    loop {
        // TODO: Handle errors in a more sane way. :wink:
        let siginfo = sfd.read_signal().expect("waiting for signal").unwrap();
        let signum = Signal::from_c_int(siginfo.ssi_signo as c_int).unwrap();

        let result = match signum {
            Signal::SIGCHLD => {
                match reap_zombies() {
                    Ok(pids) => Ok(pids.contains(&pid)),
                    Err(err) => Err(err),
                }
            },
            _ => forward_signal(&pid, signum),
        };

        match result {
            Ok(true) => break,
            Ok(_)    => continue,
            Err(err) => println!("[!] Hit an error in handling {:?}: {}", signum, err),
        };
    }

    println!("[+] Child has exited, we are done.");
}
