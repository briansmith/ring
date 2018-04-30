*ring* inherited C, C++, and assembly language code from BoringSSL, and the
style guidelines for that code are in the second section of this document.


# *ring* Style Guide (for code not in [crypto/](crypto))

*ring* usually follows the [Rust Guidelines](https://aturon.github.io/), but
there are some differences and *ring* adds additional guidelines.

## Imports (`use`) and Qualification

In general, import modules, not non-module items, e.g. `use core`, not
`use core::mem::size_of_val`. This means that the uses of such functions must
be qualified: `core::mem::size_of_val(x)`, not `size_of_val(x)`. Exceptions may
be made for things that are very annoying to qualify; for example, we usually
`use super::input::*` or `use super::input::Input` because writing things like
`input::Input` is highly annoying.

## Submodules and file naming.

In general, avoid nesting modules and avoid exporting any non-module items from
the main `ring` crate. Instead, prefer a flat module structure that is one
level deep. Thus, for example, we have `ring::digest::SHA256` but not
`ring::SHA256` or `ring::digest::sha256::SHA256` or `ring::digest::sha2::SHA256`.

Sometimes it is useful to break up a module's source code into multiple files.
In this case, it is useful to make use of the Rust visibility rule where a
submodule can use non-public items defined in the enclosing module. In that
case, it is OK to use nested submodules. The nested submodules must be
non-public (`mod x`, not `pub mod x`) and the enclosing module must re-export,
using `pub use submodule::x`, the items that are intended to be public. This
way, the implementation details that drove the choice to use nested submodules
do not affect the public API.
```

Note that this is only necessary when the module has submodules.

## Error checking

Use `Result<T, ()>` as the return type for functions that may fail. Never use
`Option<T>` or `bool` or other types as return values to indicate failure.
`Result` is used because it is annotated `#[must_use]`, so the Rust compiler
will not let callers silently ignore the return value of functions that return
`Result`s.

*ring* functions generally do not report error codes for a variety of reasons;
when they fail, they only report that they fail. If a function only needs to
return a boolean indicator that it succeeded or failed, use `Result<(), ()>` as
the return type.

If an external function (e.g. part of the Rust standard library) returns
`Option<T>` to indicate failure, use `ok_or(())` to map it to `Result<T, ()>`.
When the last statement `x` in a function is already the same `Result<T, ()>`
type that the function returns, just make that statement the return expression;
that is, write `x`, not `let result = try!(x); Ok(result)`.

Use the early-return-on-failure pattern by wrapping calls to functions that may
fail with `try!()`. Do not use `Result::or_else`, `Result::and`, etc. to chain
together strings of potentially-failing operations.

```rust
// The return type is of the form `Result<_, ()>`, not `Option<_>` or something
// else.
fn good_example(x: u32, y: u32) -> Result<u32, ()> {
    // * `ok_or` is used to map `Option<u32>` to `Result<u32, ()>` here.
    // * `try!` is used to return early on failure.
    let sum = try!(x.checked_add(y).ok_or(()));

    // Early return is used.
    try!(foo(sum));

    // `try!()` isn't used when the last statement is already of the form
    // `Result<_, ()>`.
    bar(sum)
}
```

## Arrays and Slices

When creating a slice from the start of a indexable value, use `x[..n]`, not
`x[0..n]`. Similarly, use `x[n..]`, not `x[n..x.len()]` for creating a slice
from a specific point to the end of the value.

When copying and filling arrays and slices, use the functions in
[ring::polyfill](src/polyfill.rs) when possible.

## Casting (`as`) and Conversions

Avoid using the `as` operator. When using `as` seems necessary, see if there is
already a safer function for doing the conversion in
[ring::polyfill](src/polyfill.rs). If not, add one to `ring::polyfill`.

The C code generally uses the C `int` type as a return value, where 1 indicates
success and 0 indicates failure. Sometimes the C code has functions that return
pointers, and a NULL pointer indicates failure. The module
[ring::bssl](src/bssl.rs) contains some utilities for mapping these return
values to `Result<(), ()>` and `Result<*mut T, ()>`, respectively. They should
be used as in the following example (note the placement of `unsafe`):
```rust
fn foo() -> Result<(), ()> {
    try!(bssl::map_result(unsafe {
        unsafe_fn2(when, the, entire, thing, does, not, fit, on, a, single,
                   line)
    }));

    try!(bssl::map_result(unsafe {
        unsafe_fn1() // Use the same style even when the call fits on one line.
    }));

    let ptr = try!(bssl::map_ptr_result(unsafe {
        unsafe_fn_returning_pointer()
    }));

    // The return value of `foo` will be the mapped result of calling
    // `unsafe_fn3`.
    bssl::map_result(unsafe {
        unsafe_fn3()
    })
}
```

## Arithmetic and Overflows

In general, prefer using unsigned types over signed types, and prefer using
checked arithmetic (e.g. `x.checked_add(y)`, `x.checked_mul(y)`, etc.) over
unchecked arithmetic. Prefer using checked arithmetic over explicit bounds
checks. Example:
```rust
fn good_example(a: u64, b: u64) -> Result<u64, ()> {
    let n = a.checked_add(b).ok_or(());
}

fn bad_example(a: u64, b: u64) -> Result<u64, ()> {
    if usize::max_value() - a > b {
        return Err(());
    }
    Ok(a + b)
}
```

## Unsafe

In general, avoid using `unsafe` whenever it is practical to do so. The *ring*
developers chose to use Rust because of the goodness of the safe subset; stuff
that requires `unsafe` is generally better off being written in C or assembly
language code. Generally, this means that `unsafe` is only used to call
functions written in C or assembly language. Even if your goal is to replace C
and/or assembly language code with Rust code, don't be afraid to leave, or even
add, C code to avoid adding a load of `unsafe` Rust code.

In particular, prefer references and indexing (which is checked at runtime) to
pointers and pointer arithmetic. Example:
```rust
fn good_example(x: &[u8], n: usize) {
    unsafe {
        unsafe_fn(x[n..].as_ptr()) // The compiler inserts bounds checks for us.
    }
}

fn bad_example(x: &[u8], n: usize) {
    unsafe {
        // If we do things this way, the compiler won't do bounds checking for
        // us. Also, since `offset` takes an `isize`, we have to do a cast from
        // `usize` to `isize` which is potentially unsafe because an `isize`
        // cannot hold every positive value of `usize`.
        unsafe_fn(x.as_ptr().offset(n as isize))
    }
}
```

When you must use `unsafe`, minimize the scope of `unsafe`. Example:
```rust
fn good_example() {
   unsafe { unsafe_fn(); }
   safe_fn();
   unsafe { unsafe_fn(); }
}

fn bad_example() {
    unsafe {
        unsafe_fn();
        safe_fn(); // No safe statements allowed in an unsafe block.
        unsafe_fn();
    }
}
```

But, don't go overboard:
```rust
fn ok_example(x: &[u8], n: usize) {
    unsafe {
        unsafe_fn1(x[n]); // `x[n]` is a safe expression
    }
}

fn bad_example(x: &[u8], n: usize) {
    let x_n = x[n]; // This is going overboard.
    unsafe {
        unsafe_fn1(x_n);
    }
}
```



# BoringSSL Style Guide (for code in [crypto/](crypto) and [include/](include))

BoringSSL usually follows the
[Google C++ style guide](https://google.github.io/styleguide/cppguide.html),
The rest of this section describes differences and clarifications on
top of the base guide.


## Legacy code

As a derivative of OpenSSL, BoringSSL contains a lot of legacy code that
does not follow this style guide. Particularly where public API is
concerned, balance consistency within a module with the benefits of a
given rule. Module-wide deviations on naming should be respected while
integer and return value conventions take precedence over consistency.

Modules from OpenSSL's legacy ASN.1 and X.509 stack are retained for
compatibility and left largely unmodified. To ease importing patches from
upstream, they match OpenSSL's new indentation style. For Emacs,
`doc/openssl-c-indent.el` from OpenSSL may be helpful in this.


## Language

The majority of the project is in C, so C++-specific rules in the
Google style guide do not apply. Support for C99 features depends on
our target platforms. Typically, Chromium's target MSVC is the most
restrictive.

Variable declarations in the middle of a function are allowed.

Comments should be `/* C-style */` for consistency.

When declaration pointer types, `*` should be placed next to the variable
name, not the type. So

    uint8_t *ptr;

not

    uint8_t* ptr;

Rather than `malloc()` and `free()`, use the wrappers `OPENSSL_malloc()`
and `OPENSSL_free()`. Use the standard C `assert()` function freely.

For new constants, prefer enums when the values are sequential and typed
constants for flags. If adding values to an existing set of `#define`s,
continue with `#define`.


## Formatting

Single-statement blocks are not allowed. All conditions and loops must
use braces:

    if (foo) {
      do_something();
    }

not

    if (foo)
      do_something();


## Integers

Prefer using explicitly-sized integers where appropriate rather than
generic C ones. For instance, to represent a byte, use `uint8_t`, not
`unsigned char`. Likewise, represent a two-byte field as `uint16_t`, not
`unsigned short`.

Sizes are represented as `size_t`.

Within a struct that is retained across the lifetime of an SSL
connection, if bounds of a size are known and it's easy, use a smaller
integer type like `uint8_t`. This is a "free" connection footprint
optimization for servers. Don't make code significantly more complex for
it, and do still check the bounds when passing in and out of the
struct. This narrowing should not propagate to local variables and
function parameters.

When doing arithmetic, account for overflow conditions.

Except with platform APIs, do not use `ssize_t`. MSVC lacks it, and
prefer out-of-band error signaling for `size_t` (see Return values).


## Naming

Follow Google naming conventions in C++ files. In C files, use the
following naming conventions for consistency with existing OpenSSL and C
styles:

Define structs with typedef named `TYPE_NAME`. The corresponding struct
should be named `struct type_name_st`.

Name public functions as `MODULE_function_name`, unless the module
already uses a different naming scheme for legacy reasons. The module
name should be a type name if the function is a method of a particular
type.

Some types are allocated within the library while others are initialized
into a struct allocated by the caller, often on the stack. Name these
functions `TYPE_NAME_new`/`TYPE_NAME_free` and
`TYPE_NAME_init`/`TYPE_NAME_cleanup`, respectively. All `TYPE_NAME_free`
functions must do nothing on `NULL` input.

If a variable is the length of a pointer value, it has the suffix
`_len`. An output parameter is named `out` or has an `out_` prefix. For
instance, For instance:

    uint8_t *out,
    size_t *out_len,
    const uint8_t *in,
    size_t in_len,

Name public headers like `include/GFp/evp.h` with header guards like
`OPENSSL_HEADER_EVP_H`. Name internal headers like
`crypto/ec/internal.h` with header guards like
`OPENSSL_HEADER_EC_INTERNAL_H`.

Name enums like `enum unix_hacker_t`. For instance:

    enum should_free_handshake_buffer_t {
      free_handshake_buffer,
      dont_free_handshake_buffer,
    };


## Return values

As even `malloc` may fail in BoringSSL, the vast majority of functions
will have a failure case. Functions should return `int` with one on
success and zero on error. Do not overload the return value to both
signal success/failure and output an integer. For example:

    OPENSSL_EXPORT int CBS_get_u16(CBS *cbs, uint16_t *out);

If a function needs more than a true/false result code, define an enum
rather than arbitrarily assigning meaning to int values.

If a function outputs a pointer to an object on success and there are no
other outputs, return the pointer directly and `NULL` on error.


## Parameters

Where not constrained by legacy code, parameter order should be:

1. context parameters
2. output parameters
3. input parameters

For example,

    /* CBB_add_asn sets |*out_contents| to a |CBB| into which the contents of an
     * ASN.1 object can be written. The |tag| argument will be used as the tag for
     * the object. It returns one on success or zero on error. */
    OPENSSL_EXPORT int CBB_add_asn1(CBB *cbb, CBB *out_contents, uint8_t tag);


## Documentation

All public symbols must have a documentation comment in their header
file. The style is based on that of Go. The first sentence begins with
the symbol name, optionally prefixed with "A" or "An". Apart from the
initial mention of symbol, references to other symbols or parameter
names should be surrounded by |pipes|.

Documentation should be concise but completely describe the exposed
behavior of the function. Pay special note to success/failure behaviors
and caller obligations on object lifetimes. If this sacrifices
conciseness, consider simplifying the function's behavior.

    // EVP_DigestVerifyUpdate appends |len| bytes from |data| to the data which
    // will be verified by |EVP_DigestVerifyFinal|. It returns one on success and
    // zero otherwise.
    OPENSSL_EXPORT int EVP_DigestVerifyUpdate(EVP_MD_CTX *ctx, const void *data,
                                              size_t len);

Explicitly mention any surprising edge cases or deviations from common
return value patterns in legacy functions.

    // RSA_private_encrypt encrypts |flen| bytes from |from| with the private key in
    // |rsa| and writes the encrypted data to |to|. The |to| buffer must have at
    // least |RSA_size| bytes of space. It returns the number of bytes written, or
    // -1 on error. The |padding| argument must be one of the |RSA_*_PADDING|
    // values. If in doubt, |RSA_PKCS1_PADDING| is the most common.
    //
    // WARNING: this function is dangerous because it breaks the usual return value
    // convention. Use |RSA_sign_raw| instead.
    OPENSSL_EXPORT int RSA_private_encrypt(int flen, const uint8_t *from,
                                           uint8_t *to, RSA *rsa, int padding);

Document private functions in their `internal.h` header or, if static,
where defined.


## Build logic

BoringSSL is used by many projects with many different build tools.
Reimplementing and maintaining build logic in each downstream build is
cumbersome, so build logic should be avoided where possible. Platform-specific
files should be excluded by wrapping the contents in `#ifdef`s, rather than
computing platform-specific file lists. Generated source files such as perlasm
and `err_data.c` may be used in the standalone CMake build but, for downstream
builds, they should be pre-generated in `generate_build_files.py`.
