THE SOFTWARE IS PROVIDED "AS IS" AND BRIAN SMITH AND THE AUTHORS DISCLAIM
ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL BRIAN SMITH OR THE AUTHORS
BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.



*ring*
======

*ring* is focused on the implementation, testing, and optimization of a core
set of cryptographic operations exposed via an easy-to-use (and hard-to-misuse)
API. *ring* exposes a [Rust](https://www.rust-lang.org/) API and is written in
a hybrid of Rust, C, and assembly language.

Particular attention is being paid to making it easy to build and integrate
*ring* into applications and higher-level frameworks, and to ensuring that
*ring* works optimally on small devices, and eventually microcontrollers, to
support Internet of Things (IoT) applications.

Most of the C and assembly language code in *ring* comes from BoringSSL, and
BoringSSL is derived from OpenSSL. *ring* merges changes from BoringSSL
regularly. Also, several changes that were developed for *ring* have been
contributed to and integrated into BoringSSL.



Documentation
-------------

See the documentation at https://docs.rs/ring/latest/ring/.

See [BUILDING.md](BUILDING.md) for instructions on how to build it. These
instructions are especially important for cross-compiling and for building on
Windows when not building from crates.io, as there are build prerequisites that
need to be installed.



Benchmarks
----------

*ring*'s benchmarks are located in the `bench` folder of this repository. Because
there is lots of platform-specific code in *ring*, and because *ring* chooses
dynamically at runtime which optimized implementation of each crypto primitive
to use, it is very difficult to publish a useful single set of benchmarks;
instead, you are highly encouraged to run the benchmarks yourselves on your
target hardware.




Contributing
------------

The most important contributions are *uses* of *ring*. That is, we're very
interested in seeing useful things built on top of *ring*, like implementations
of TLS, SSH, the Noise Protocol, etc.

The *ring* project happily accepts pull requests. The portions of pull requests
that modify existing files must be licensed under the same terms as the files
being  modified. New files in pull requests, including in particular all Rust
code, must be licensed under the ISC-style license. Please state that you agree
to license your contributions in the commit messages of commits in pull
requests by putting this at the bottom of your commit message:

```

I agree to license my contributions to each file under the terms given
at the top of each file I changed.
```



Minimum Supported Rust Version (MSRV)
-------------------------------------

*ring* is tested on the latest Stable, Beta, and Nightly releases of Rust,
as well as the oldest version known to work according to the tests run in CI.
That oldest version known to work is documented as the MSRV in
[Cargo.toml](Cargo.toml). 



Bug Reporting
-------------

Please see [SECURITY.md](SECURITY.md) for help on reporting security vulnerabilities.

Please report bugs that aren't security vulnerabilities either as pull requests or as issues in
[the issue tracker](https://github.com/briansmith/ring/issues).


License
-------

See [LICENSE](LICENSE).
