// Copyright 2026 Brian Smith.
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

#![allow(missing_docs)]

use self::path::join_components_with_forward_slashes_if_windows;
use std::{ffi::OsStr, path::Path};

#[allow(dead_code)]
#[path = "../build/build/path.rs"]
mod path;

#[test]
fn join_components_with_forward_slashes_tests() {
    struct Case {
        input: &'static str,
        expected_windows: &'static str,
    }
    const VALID_TEST_CASES: &[Case] = &[
        Case {
            input: r#"/"#,
            expected_windows: "/",
        },
        Case {
            input: r#"//"#,
            expected_windows: "/",
        },
        Case {
            input: r#"\"#,
            expected_windows: "/",
        },
        Case {
            input: r#"\\"#,
            expected_windows: "/",
        },
        Case {
            input: r#"\\foo"#,
            expected_windows: "/foo",
        },
        Case {
            input: r#"\\foo\bar"#,
            expected_windows: "//foo/bar/", // UNC with implied root
        },
        Case {
            input: r#"//foo"#,
            expected_windows: "/foo", // Redundant slash removed.
        },
        Case {
            input: r#"//foo/bar"#,
            expected_windows: "//foo/bar/", // UNC with implied root
        },
        Case {
            input: r#"\\server\share"#,
            expected_windows: "//server/share/", // UNC with implied root
        },
        Case {
            input: r#"\\server\share\"#,
            expected_windows: "//server/share/", // UNC
        },
        Case {
            input: r#"\\server\share\foo"#,
            expected_windows: "//server/share/foo", // UNC
        },
        Case {
            input: r#"\\server\share\foo\bar"#,
            expected_windows: "//server/share/foo/bar", // UNC
        },
        Case {
            // XXX: trailing slash stripped
            input: r#"\\server\share\foo\bar\"#,
            expected_windows: "//server/share/foo/bar", // UNC
        },
        Case {
            input: r#"//server/share"#,
            expected_windows: "//server/share/", // UNC with implied root
        },
        Case {
            input: r#"//server/share/"#,
            expected_windows: "//server/share/", // UNC
        },
        Case {
            input: r#"//server/share/foo"#,
            expected_windows: "//server/share/foo", // UNC
        },
        Case {
            input: r#"//server/share/foo/bar"#,
            expected_windows: "//server/share/foo/bar", // UNC
        },
        Case {
            // XXX: trailing slash stripped
            input: r#"//server/share/foo/bar/"#,
            expected_windows: "//server/share/foo/bar", // UNC
        },
        Case {
            input: r#"//server\share"#,
            expected_windows: "//server/share/", // UNC with implied root
        },
        Case {
            input: r#"//server\share/"#,
            expected_windows: "//server/share/", // UNC
        },
        Case {
            input: r#"//server\share/foo"#,
            expected_windows: "//server/share/foo", // UNC,
        },
        Case {
            input: r#"//server\share/foo/bar"#,
            expected_windows: "//server/share/foo/bar", // UNC
        },
        Case {
            // XXX: trailing slash stripped
            input: r#"//server\share/foo/bar/"#,
            expected_windows: "//server/share/foo/bar", // UNC
        },
        Case {
            input: r#"\\server\share"#,
            expected_windows: "//server/share/", // UNC with implied root
        },
        Case {
            input: r#"\\server\share/"#,
            expected_windows: "//server/share/", // UNC
        },
        Case {
            input: r#"\\server\share/foo"#,
            expected_windows: "//server/share/foo", // UNC
        },
        Case {
            input: r#"\\server\share/foo/bar"#,
            expected_windows: "//server/share/foo/bar", // UNC
        },
        Case {
            // XXX: trailing slash stripped
            input: r#"\\server\share/foo/bar/"#,
            expected_windows: "//server/share/foo/bar", // UNC
        },
        Case {
            input: r#"//server/share\"#,
            expected_windows: "//server/share/", // UNC
        },
        Case {
            input: r#"//server/share\foo"#,
            expected_windows: "//server/share/foo", // UNC
        },
        Case {
            input: r#"//server/share/foo\bar"#,
            expected_windows: "//server/share/foo/bar", // UNC
        },
        Case {
            // XXX: trailing slash stripped
            input: r#"//server/share\foo/bar/"#,
            expected_windows: "//server/share/foo/bar",
        },
        Case {
            input: r#"C:foo"#,
            expected_windows: "C:foo",
        },
        Case {
            input: r#"C:\foo"#,
            expected_windows: "C:/foo",
        },
        Case {
            input: r#"C:/foo"#,
            expected_windows: "C:/foo",
        },
        Case {
            input: r#"a\b"#,
            expected_windows: "a/b",
        },
        Case {
            input: r#"/a/b"#,
            expected_windows: "/a/b",
        },
        Case {
            input: r#"\a\b"#,
            expected_windows: "/a/b",
        },
        Case {
            input: r#".\b"#,
            expected_windows: "./b",
        },
        Case {
            input: r#"../b"#,
            expected_windows: "../b",
        },
        Case {
            input: r#"a/../b"#,
            expected_windows: "a/../b",
        },
        Case {
            // XXX: Trailing slash is skipped.
            input: r#"a/./b/"#,
            expected_windows: "a/b",
        },
    ];

    let failures = VALID_TEST_CASES
        .iter()
        .filter_map(
            |Case {
                 input,
                 expected_windows,
             }| {
                let actual = join_components_with_forward_slashes_if_windows(Path::new(input));
                let expected = if cfg!(windows) {
                    expected_windows
                } else {
                    input
                };
                if actual == AsRef::<OsStr>::as_ref(expected) {
                    None
                } else {
                    Some((input, actual, expected))
                }
            },
        )
        .collect::<Vec<_>>();
    assert_eq!(failures, &[]);
}
