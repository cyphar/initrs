# THIS REPOSITORY IS OUTDATED AND ARCHIVED -- PLEASE SWITCH TO [CATATONIT](https://github.com/openSUSE/catatonit). #

## `initrs` ##

[![Build Status](https://travis-ci.org/cyphar/initrs.svg?branch=master)](https://travis-ci.org/cyphar/initrs)

A **truly** simple init for containers. It handles zombie reaping and signal
forwarding in as simple a way as possible. It is effectively a rewrite of the
current `docker-init` implementation, [tini][tini] which I would argue is not
as simple as it should be.

[tini]: https://github.com/krallin/tini

### License ###

`initrs` is licensed under the terms of the GNU GPLv3 (or later).

```
initrs: simple init for containers
Copyright (C) 2017, 2018 SUSE LLC.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
```
