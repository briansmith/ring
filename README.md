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
*ring* works optimally on microcontrollers to support Internet of Things
(IoT) applications.

The name *ring* comes from the fact that *ring* started as a subset of
BoringSSL, and *"ring"* is a substring of "Bo*ring*SSL". Almost all the code in
*ring* comes from BoringSSL, and BoringSSL is derived from OpenSSL. In general
an application that uses the subset of BoringSSL APIs that *ring* supports
should work identically if it is recompiled and relinked with BoringSSL
instead. *ring* tracks upstream changes to BoringSSL. Several patches that
were developed for *ring* have already been integrated upstream in BoringSSL.



Documentation
-------------

See the documentation at
https://briansmith.org/rustdoc/ring/.

See [Building the Rust Library](BUILDING.md#building-the-rust-library) for
instructions on how to build it.



Contributing
------------

Patches Welcome! Suggestions:

* More code elimination, especially dead code.
* Replacing more C code with Rust code.
* Implementation of [SRP-6a](http://srp.stanford.edu/) in Rust, based on the
  |rust::digest| API and the C/asm optimized modular exponentiation.
* Optimizing the PBKDF2-HMAC implementation based on the ideas from
  [fastpbkdf2](https://github.com/ctz/fastpbkdf2).
* Better IDE support for Windows (e.g. running the tests within the IDE) and
  Mac OS X (e.g. Xcode project files).
* Support for more platforms in the continuous integration (e.g. Android, iOS,
  ARM microcontrollers).
* Static analysis and fuzzing in the continuous integration.



License
-------

See [LICENSE](LICENSE).

The *ring* project happily accepts pull requests without any copyright license
agreement. The portions of pull requests that modify existing files should be
licensed under the same terms as the files being modified. New files in pull
requests, including in particular all Rust code, should be licensed under the
ISC-style license.

If your patch is useful for BoringSSL then it would be very nice of you to also
submit it to them after agreeing to their CLA.



Online Automated Testing
------------------------

Travis CI is used for Linux and Mac OS X. Appveyor is used for Windows. The
tests are run in debug and release configurations, for the current release of
each Rust channel (Stable, Beta, Nightly), for each configuration listed
in the table below.

<table>
<tr><th>OS</th><th>Arch.</th><th>Compilers</th><th>Status</th>
<tr><td>Linux</td>
    <td>x86, x64<td>GCC 4.8, 4.9, 5; Clang 3.4, 3.6, 3.7, 3.8 (trunk)</td>
    <td rowspan=2><a title="Build Status" href=https://travis-ci.org/briansmith/ring><img src=https://travis-ci.org/briansmith/ring.svg?branch=master></a>
</tr>
<tr><td>Mac OS X x64</td>
    <td>x86, x64</td>
    <td>Apple Clang 6.0 (based on Clang 3.5)</td>
</tr>
<tr><td>Windows</td>
    <td>x86, x64</td>
    <td>MSVC 2013 Update 5 (12.0), MSVC 2015 Update 1 (14.0)</td>
    <td><a title="Build Status" href=https://ci.appveyor.com/project/briansmith/ring/branch/master><img src=https://ci.appveyor.com/api/projects/status/3wq9p54r9iym05rm/branch/master?svg=true></a>
</tr>
</table>



Bug Reporting
-------------

Please file bugs in the
[issue tracker](https://github.com/briansmith/ring/issues). If you think you've
found a security vulnerability that affects BoringSSL and/or OpenSSL then those
projects would probably appreciate it if you report the bug privately to them.
The *ring* project is happy to take *any* kind of bug report as a pull request
that fixes it and/or adds a test for the issue, or as an issue filed in the
public issue tracker. **Do NOT report any security vulnerability privately to
the *ring* developers.**
