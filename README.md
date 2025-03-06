THE SOFTWARE IS PROVIDED "AS IS" AND BRIAN SMITH AND THE AUTHORS DISCLAIM
ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL BRIAN SMITH OR THE AUTHORS
BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.


Most of the C and assembly language code in *ring* comes from BoringSSL. 
BoringSSL is a fork of OpenSSL. This quote from the BoringSSL README.md 
discouraging you from using it applies to this project:

> BoringSSL is a fork of OpenSSL that is designed to meet Google's needs.
>
> Although BoringSSL is an open source project, it is not intended for general
> use, as OpenSSL is. We don't recommend that third parties depend upon it.

This project was originally shared on GitHub in 2015 as an experiment. It was
put on crates.io shortly to help other people with their experiments. It is an
experiment.


Side Channels
-------------

This project uses coding patterns that attempt to reduce the risk that the
compiler will generate machine code that will leak secrets through timing side
channels. This project uses similar mitigations as BoringSSL, but they are not
exactly the same, they are not used in exactly the same way. BoringSSL seems to
have some ways of validating that its mitigations work with specific versions
of specific C/C++ compilers. This project kinda relies on that; this should be
revisited.

There are some targets where trying to be "constant-time" just isn't going to
work.

For WebAssembly and WebAssembly-like targets, where there is a JIT, virtual
machine, or similar intermediary involved, the runtime is likely to undo
whatever we do to mitigate timing side channels. Even with the introduction of
blinding, there is a big risk for these targets. WebAssembly itself needs to
develop solutions for solving these problems.

There are "native" targets that have similar issues. BoringSSL will refuse to
compile for some of them because of its allowlist of targets. *ring* doesn't
use that allowlist, and also the allowlist doesn't completely avoid the
problem.

*ring* doesn't use any randomizing mitigations like blinding.

Over time, as compiler evolved, mitigations for compiler-introduced side
channels have had to evolve. What worked years ago with version X of the C
compiler doesn't necessarily work now with version X+1, or even with the same
version of the compiler shipped by a different vendor or configured in a
different way. This probably affects this project's releases and would probably
affect the project more and more over time going forward.

Over time *ring* and BoringSSL have diverged in various areas. In some cases
*ring* was ahead of BoringSSL regarding mitigations for timing side channels
using our own code. For example, there was a time when we replaced much of the
ECC code and RSA code that was using variable-length `BIGNUM` arithmetic with
similar fixed-length bigint arithmetic. However, since then, BoringSSL has come
up with its own similar but different solution. Similarly, because of our hopes
of eventually getting rid of the C code in *ring*, and the hope of eventually
minimizing the use of external assembly code, and other difficulties, in some
situations this project uses a substantially different implementation of a
primitive than BoringSSL may use. This is something to be investigated.

Recently, BoringSSL has converted most of its code from C to C++, whereas
*ring* still uses the C variant of that code. This would naturally make sharing
code hard unless we also switch to requiring a C++ compiler for *ring*. And of
course this even further reduces the validity of relying on BoringSSL's testing
for *ring*.

Besides all of the above, there are many other things to consider regarding
timing side channels and other kinds of side channels.



Bug Reporting
-------------

For security vulnerabilities, see https://github.com/briansmith/ring/security/policy.

Please report bugs that aren't security vulnerabilities either as pull requests or as issues in
[the issue tracker](https://github.com/briansmith/ring/issues).



Release Notes
-------------
It is recommended that you review every commit in this project. Some
particularly noteworthy changes are noted in the [RELEASES.md](RELEASES.md). We could use some
help in making this better.
