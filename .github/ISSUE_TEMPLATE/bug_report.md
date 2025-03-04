---
name: Bug report
about: I think I found a bug
title: ''
labels: ''
assignees: ''

---

Please do report bugs you find, especially if something is calculated
incorrectly, something is rejected when it should be accepted,
something is accepted but should be rejected, etc.

Email brian@briansmith.org for business inquiries including sponsorships,
funded feature requests, etc.

If your build was working previously and now fails after updating to a new
version, and the changelog doesn't call out an intended increase in build
tool requirements--i.e. there is a regression in the build system--please DO
report a bug.

Otherwise, please try to identify the cause and solution of a build failure
before filing an issue. This project isn't as easy to build as most other Rust
projects. Most bug reports are about really asking for help figuring out how to
configure the build. `mk/cargo.sh`, `mk/install-build-tools.{sh,ps1}`, and the
GitHub Actions  configuration contain plenty of examples of how to build this.
There is a discussion category
https://github.com/briansmith/ring/discussions/categories/building for
people to help each other with build issues.

The best way to request a port to a target that we haven't tried to support is
to submit a PR that modifies `mk/cargo.sh` and `mk/install-build-tools.{sh,ps1}`
to make it easy for people to test the port (in QEMU).
