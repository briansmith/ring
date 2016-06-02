THE SOFTWARE IS PROVIDED "AS IS" AND BRIAN SMITH AND THE AUTHORS DISCLAIM
ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL BRIAN SMITH OR THE AUTHORS
BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.



*ring*
======

*ring* is a crypto library in Rust based on BoringSSL's crypto primitive
implementations.

Particular attention is being paid to making it easy to build and integrate
*ring* into applications and higher-level frameworks, and to ensuring that
*ring* works optimally on small devices, and eventually microcontrollers, to
support Internet of Things (IoT) applications.

The name *ring* comes from the fact that *ring* started as a subset of
BoringSSL, and *"ring"* is a substring of "Bo*ring*SSL". Most of the (C and
assembly language) code in *ring* comes from BoringSSL, and BoringSSL is
derived from OpenSSL. *ring* merges changes from BoringSSL regularly. Also,
several changes that were developed for *ring* have already been merged into
BoringSSL.



Documentation
-------------

See the documentation at
https://briansmith.org/rustdoc/ring/.

See [BUILDING.md](BUILDING.md#building-the-rust-library) for instructions on
how to build it. These instructions are especially important on Windows, as
there are build prerequisites that need to be installed.



Contributing
------------

The *ring* project happily accepts pull requests without you needing to sign
any formal license agreement. The portions of pull requests that modify
existing files must be licensed under the same terms as the files being
modified. New files in pull requests, including in particular all Rust code,
must be licensed under the ISC-style license. Please state that you agree to
license your contributions in the commit messages of commits in pull requests,
e.g. by putting this at the bottom of your commit message:

```

I agree to license my contributions to each file under the terms given
at the top of each file I changed.
```

The most important contributions are *uses* of *ring*. That is, we're very
interested in seeing useful things built on top of *ring*, like implementations
of TLS, SSH, the Noise Protocol, etc.

Of course, contributions to *ring*'s code base are highly appreciated too. If
you want to work directly on *ring* and you don't have an idea for something to
contribute already, see the [issues marked
`good-first-bug`](https://github.com/briansmith/ring/issues?q=is%3Aopen+is%3Aissue+label%3Agood-first-bug)
in the issue tracker.

In addition, we're always interested in these kinds of contributions:

* Bug fixes.
* Additional testing code and additional test vectors.
* Documentation improvements.
* More code simplification, especially eliminating dead code.
* Replacing more C code with Rust code.
* Improving the code size, execution speed, and/or memory footprint.
* Making more features work in the `no_heap`/`#![no_std]` mode, by avoiding
  uses of the heap.
* Better IDE support for Windows (e.g. running the tests within the IDE) and
  Mac OS X (e.g. Xcode project files).
* Support for more platforms in the continuous integration (e.g. Android, iOS,
  ARM microcontrollers).
* Static analysis and fuzzing in the continuous integration.



Online Automated Testing
------------------------

Travis CI is used for Android, Linux, and Mac OS X. Appveyor is used for
Windows. The tests are run in debug and release configurations, for the current
release of each Rust channel (Stable, Beta, Nightly), for each configuration
listed in the table below.

<table>
<tr><th>OS</th><th>Arch.</th><th>Compilers</th><th>Status</th>
<tr><td rowspan=2>Linux</td>
    <td>x86, x86_64</td>
    <td>GCC 4.6, GCC 5, Clang 3.8. (Clang builds are temporarily disabled due
        to the current LLVM APT repo outage.)</td>
    <td rowspan=4><a title="Build Status" href=https://travis-ci.org/briansmith/ring><img src=https://travis-ci.org/briansmith/ring.svg?branch=master></a>
</tr>
<tr><td>32&#8209;bit&nbsp;ARM, AAarch64</td>
    <td>GCC (Ubuntu/Linaro 4.8.4-2ubuntu1~14.04.1), tested using
        <code>qemu-user-arm</code>.</td>
</tr>
<tr><td>Android</td>
    <td>32&#8209;bit&nbsp;ARM</td>
    <td>Built using the Android SDK 24.4.1 and Android NDK 10e, tested using
        the Android emulator. (Aarch64 builds are blocked on the Rust team
        producing AAarch64 builds of Rust's libstd.)</td>
</tr>
<tr><td>Mac&nbsp;OS&nbsp;X</td>
    <td>x64</td>
    <td>Apple Clang 7.0.2 (clang-700.1.81)</td>
</tr>
<tr><td>Windows</td>
    <td>x86, x86_64</td>
    <td>MSVC 2015 Update 2 (14.0)</td>
    <td><a title="Build Status" href=https://ci.appveyor.com/project/briansmith/ring/branch/master><img src=https://ci.appveyor.com/api/projects/status/3wq9p54r9iym05rm/branch/master?svg=true></a>
</tr>
</table>



Bug Reporting
-------------

Please report bugs either as pull requests or as issues in [the issue
tracker](https://github.com/briansmith/ring/issues). *ring* has a
**full disclosure** vulnerability policy. **Please do NOT attempt to report
any security vulnerability in this code privately to anybody.**



License
-------

See [LICENSE](LICENSE).
