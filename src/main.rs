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

use std::process::Command;

#[macro_use]
extern crate clap;
use clap::{App, Arg, AppSettings};

fn main() {
    let options = App::new("initrs")
                      .setting(AppSettings::TrailingVarArg)
                      .author("Aleksa Sarai <asarai@suse.de>")
                      .version(crate_version!())
                      .about("Simple init for containers.")
                      // Represents the actual command to be run.
                      .arg(Arg::with_name("command")
                               .multiple(true))
                      .get_matches();

    let args = options.values_of("command").unwrap()
                      .collect::<Vec<_>>();

    let (cmd, args) = args.as_slice()
                          .split_first().unwrap();

    // We have to prepare a command.
    let status = Command::new(cmd)
                         .args(args)
                         .status().unwrap();
    assert!(status.success());
}
