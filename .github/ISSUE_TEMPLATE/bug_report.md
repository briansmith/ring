---
name: Bug report
about: I think I found a bug
title: ''
labels: ''
assignees: ''

---

Please do report bugs you find, especially if something is calculated incorrectly, something is rejected when it should be accepted, something is accepted but should be rejected, etc.

Please do not submit bug reports requesting new features.

Please do not submit bug reports requesting ports to new platforms. That is a feature request.

Please do not submit bug reports caused by build failures unless you are *confident* that it is a true bug and not a build configuration issue. This project isn't as easy to build as other Rust projects. Most bug reports are about really asking for help figuring out how to configure the build. `mk/cargo.sh`, `mk/install-build-tools.{sh,ps1}`, and the GitHub Actions configuration contain plenty of examples of how to build this.
