THE SOFTWARE IS PROVIDED "AS IS" AND BRIAN SMITH AND THE AUTHORS DISCLAIM
ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL BRIAN SMITH OR THE AUTHORS
BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.



What is *ring*?
===============

*ring* is a simplified version of BoringSSL with C and Rust APIs.

*ring* makes OpenSSL's high-quality, high-performance crypto primitives
conveniently available to new crypto libraries written in safer (than C)
languages like OCaml and Rust. Particular attention is being paid to making it
easy to build and integrate *ring* into applications and higher-level
frameworks, and to ensuring that *ring* works optimally on microcontrollers
to support Internet of Things (IoT) applications. It may also be useful for
people implementing cryptographic protocols in C and C++.

The name *ring* comes from the fact that *ring* started as a subset of
BoringSSL, and *"ring"* is a substring of "Bo*ring*SSL". Almost all the code in
*ring* comes from BoringSSL, and BoringSSL is derived from OpenSSL. In general
an application that uses the subset of BoringSSL APIs that *ring* supports
should work identically if it is recompiled and relinked with BoringSSL
instead. *ring* tracks upstream changes to BoringSSL. Several patches that
were developed for *ring* have already been integrated upstream in BoringSSL.



The Rust API
============
The first part of the ```ring``` Rust crate is now available.

Currently these features are supported through the Rust API:

* Cryptographic digests (SHA-256, SHA-384, SHA-512, SHA-1, and MD5).
* RSA PKCS#1 Signature Verification.
* ECDSA Signature Verification for curves P-256, P-384, and P-521.

See the documentation at
https://briansmith.github.io/ring/ring/. Also take a look at the example
program [checkdigest.rs](examples/checkdigest.rs).

See [Building the Rust Library](BUILDING.md#building-the-rust-library) for
instructions on how to build it (hint: it's just ```cargo build```).



The C API
=========
The C API is the same as BoringSSL's, except that its SSL/TLS, X.509, and
ASN.1 APIs have been removed. See
[this](https://github.com/briansmith/ring/blob/wip/BUILDING.md#building-the-c-library-on-windows)
(for Windows) and
[this](https://github.com/briansmith/ring/blob/wip/BUILDING.md#building-the-c-library-on-linux-and-similar-platforms)
(for other platforms) for instructions on how to build *ring* and incorporate
it into your project.



Warning: The ```wip``` Branch Gets Rebased Frequently
=====================================================

The default branch on GitHub for this project is the ```wip``` branch. This
branch is getting rebased regularly as I clean up the initial set of patches
for *ring*. Once that cleanup is done, I will create a ```master``` branch that
I intend to never rebase, and then I will delete the ```wip``` branch.



Contributing
============

Patches Welcome! Suggestions:

* Better IDE support for Windows (e.g. running the tests within the IDE) and
  Mac OS X (e.g. Xcode project files).
* Language bindings for safer programming languages like Haskell, OCaml, and
  Rust.
* Support for more platforms in the continuous integration, such as Android,
  Mac OS X, and ARM microcontrollers. (The current CI only covers Linux.)
* Static analysis and fuzzing in the continuous integration.
* More code elimination, especially dead code.



License
=======

See [LICENSE](LICENSE). The *ring* project happily accepts pull requests
without any copyright license agreement. The portions of pull requests that
modify existing files should be licensed under the same terms as the files
being modified. New files in pull requests should be licensed under the
ISC-style license. If your patch is useful for BoringSSL then it would be very
nice of you to also submit it to them after agreeing to their copyright license
agreement.



Online Automated Testing
========================

Travis CI is used for Linux and Mac OS X. Appveyor is used for Windows.

<table>
<tr><th>OS</th><th>Arch.</th><th>Compilers</th><th>Status</th>
<tr><td>Linux</td>
    <td>x86, x64<td>GCC 4.8, 4.9, 5; Clang 3.4, 3.5, 3.6</td>
    <td rowspan=2><a title="Build Status" href=https://travis-ci.org/briansmith/ring><img src=https://travis-ci.org/briansmith/ring.svg?branch=wip></a>
</tr>
<tr><td>Mac OS X x64</td>
    <td>x86, x64</td>
    <td>Apple Clang 6.0 (based on Clang 3.5)</td>
</tr>
<tr><td>Windows</td>
    <td>x86, x64</td>
    <td>MSVC 2013 (12.0), 2015 (14.0)</td>
    <td><a title="Build Status" href=https://ci.appveyor.com/project/briansmith/ring/branch/wip><img src=https://ci.appveyor.com/api/projects/status/3wq9p54r9iym05rm/branch/wip?svg=true></a>
</tr>
</table>



Bug Reporting
=============

Please file bugs in the
[issue tracker](https://github.com/briansmith/ring/issues). If you think you've
found a security vulnerability that affects BoringSSL and/or OpenSSL then those
projects would probably appreciate it if you report the bug privately to them.
The *ring* project is happy to take *any* kind of bug report as a pull request
that fixes it and/or adds a test for the issue, or as an issue filed in the
public issue tracker. **Do NOT report any security vulnerability privately to
the *ring* developers.**
