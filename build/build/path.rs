// Copyright 2015-2026 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

//! Path manipulation.

use std::{
    ffi::OsString,
    fs::{self, DirEntry},
    path::{Component, Path, Prefix},
};

// TODO: Preserve trailing slash; currently this isn't needed.
pub fn join_components_with_forward_slashes_if_windows(path: &Path) -> OsString {
    if cfg!(windows) {
        // Windows and UEFI but NOT Cygwin!
        join_components_with_forward_slashes(path).expect("Verbatim paths not supported")
    } else {
        // There shouldn't be any backslashes to replace (backslash is a valid
        // path character, often) and trying to do it uniformly for all targets
        // causes problems because `std::Path::components()` doesn't parse
        // "//server/path/foo/bar" as a UNC
        // (https://github.com/rust-lang/rust/issues/154164).
        path.into()
    }
}

// TODO: Preserve trailing slash; currently this isn't needed.
fn join_components_with_forward_slashes(path: &Path) -> Option<OsString> {
    let mut result = OsString::new();
    let mut needs_separator = false;

    for component in path.components() {
        match component {
            Component::Prefix(p) => {
                assert!(result.is_empty());
                assert!(!needs_separator);
                let kind = p.kind();
                if let Prefix::UNC(server, share) = kind {
                    result.push("//");
                    result.push(server);
                    result.push("/");
                    result.push(share);
                } else if kind.is_verbatim() {
                    // We can't substitute forward slashes safely.
                    return None;
                } else {
                    result.push(p.as_os_str());
                }
                assert!(!needs_separator);
            }
            Component::RootDir => {
                // The result might not be empty if it started with another prefix like a drive.
                result.push("/");
                needs_separator = false;
            }
            Component::CurDir | Component::ParentDir | Component::Normal(_) => {
                if needs_separator {
                    result.push("/");
                }
                result.push(component.as_os_str());
                needs_separator = true;
            }
        }
    }

    Some(result)
}

pub fn walk_dir(dir: &Path, cb: &impl Fn(&DirEntry)) {
    if dir.is_dir() {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                walk_dir(&path, cb);
            } else {
                cb(&entry);
            }
        }
    }
}
