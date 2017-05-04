## `initrs` ##

A **truly** simple init for containers. It handles zombie reaping and signal
forwarding in as simple a way as possible. It is effectively a rewrite of the
current `docker-init` implementation, [tini][tini] which I would argue is not
as simple as it should be.

[tini]: https://github.com/krallin/tini
