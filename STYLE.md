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

Use the early-return-on-failure pattern using the `?` operator. Do not use
`Result::or_else`, `Result::and`, etc. to chain together strings of
potentially-failing operations.

```rust
// The return type is of the form `Result<_, ()>`, not `Option<_>` or something
// else.
fn good_example(x: u32, y: u32) -> Result<u32, ()> {
    // * `ok_or` is used to map `Option<u32>` to `Result<u32, ()>` here.
    let sum = x.checked_add(y).ok_or(())?;

    // Early return is used.
    foo(sum)?;

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
success and 0 indicates failure. The module [ring::bssl](src/bssl.rs) contains
a [transparent] `Result` type which should be used as the return type when
declaring foreign functions which follow this convention. A
`ring::bssl::Result` should be converted to a `core::result::Result` using the
pattern in the following example (note the placement of `unsafe`):

[transparent]: https://doc.rust-lang.org/nightly/reference/type-layout.html#the-transparent-representation

```rust
extern {
    unsafe_fn1() -> bssl::Result;
    /* ... */
}

fn foo() -> Result<(), ()> {
    Result::from(unsafe {
        unsafe_fn2(when, the, entire, thing, does, not, fit, on, a, single,
                   line)
    })?;

    Result::from(unsafe {
        unsafe_fn1() // Use the same style even when the call fits on one line.
    })?;

    // The return value of `foo` will be the mapped result of calling
    // `unsafe_fn3`.
    Result::from(unsafe {
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
