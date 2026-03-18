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

use self::path::{TARGET_SUPPORTS_UNCS_AND_BACKSLASHES, join_components_with_forward_slashes};
use std::{ffi::OsStr, path::Path};

#[allow(dead_code)]
#[path = "../build/build/path.rs"]
mod path;

#[test]
fn join_components_with_forward_slashes_tests() {
    struct Case {
        input: &'static str,
        expected: &'static str,
    }
    const VALID_TEST_CASES: &[Case] = &[
        Case {
            input: r#"/"#,
            expected: "/",
        },
        Case {
            input: r#"//"#,
            expected: "/",
        },
        Case {
            input: r#"\"#,
            expected: if TARGET_SUPPORTS_UNCS_AND_BACKSLASHES {
                "/"
            } else {
                r#"\"# // Backslash not interpreted as a separator
            },
        },
        Case {
            input: r#"\\"#,
            expected: if TARGET_SUPPORTS_UNCS_AND_BACKSLASHES {
                "/"
            } else {
                r#"\\"# // Backslash not interpreted as a separator
            },
        },
        Case {
            input: r#"\\foo"#,
            expected: if TARGET_SUPPORTS_UNCS_AND_BACKSLASHES {
                "/foo"
            } else {
                r#"\\foo"# // Backslash not interpreted as a separator
            },
        },
        Case {
            input: r#"\\foo\bar"#,
            expected: if TARGET_SUPPORTS_UNCS_AND_BACKSLASHES {
                "//foo/bar/" // UNC with implied root
            } else {
                r#"\\foo\bar"# // Backslash not interpreted as a separator
            },
        },
        Case {
            input: r#"//foo"#,
            expected: "/foo", // Redundant slash removed.
        },
        Case {
            input: r#"//foo/bar"#,
            expected: if TARGET_SUPPORTS_UNCS_AND_BACKSLASHES {
                "//foo/bar/" // UNC with implied root
            } else {
                "/foo/bar"
            },
        },
        Case {
            input: r#"\\server\share"#,
            expected: if TARGET_SUPPORTS_UNCS_AND_BACKSLASHES {
                "//server/share/" // UNC with implied root
            } else {
                r#"\\server\share"# // Backslash not interpreted as a separator
            },
        },
        Case {
            input: r#"\\server\share\"#,
            expected: if TARGET_SUPPORTS_UNCS_AND_BACKSLASHES {
                "//server/share/" // UNC
            } else {
                r#"\\server\share\"# // Backslash not interpreted as a separator
            },
        },
        Case {
            input: r#"\\server\share\foo"#,
            expected: if TARGET_SUPPORTS_UNCS_AND_BACKSLASHES {
                "//server/share/foo" // UNC
            } else {
                r#"\\server\share\foo"# // Backslash not interpreted as a separator
            },
        },
        Case {
            input: r#"\\server\share\foo\bar"#,
            expected: if TARGET_SUPPORTS_UNCS_AND_BACKSLASHES {
                "//server/share/foo/bar" // UNC
            } else {
                r#"\\server\share\foo\bar"# // Backslash not interpreted as a separator
            },
        },
        Case {
            // XXX: trailing slash stripped
            input: r#"\\server\share\foo\bar\"#,
            expected: if TARGET_SUPPORTS_UNCS_AND_BACKSLASHES {
                "//server/share/foo/bar" // UNC
            } else {
                r#"\\server\share\foo\bar\"# // Backslash not interpreted as a separator
            },
        },
        Case {
            input: r#"//server/share"#,
            expected: if TARGET_SUPPORTS_UNCS_AND_BACKSLASHES {
                "//server/share/" // UNC with implied root
            } else {
                r#"/server/share"# // Redundant slash removed.
            },
        },
        Case {
            input: r#"//server/share/"#,
            expected: if TARGET_SUPPORTS_UNCS_AND_BACKSLASHES {
                "//server/share/" // UNC
            } else {
                r#"/server/share"# // Redundant slash removed. XXX: trailing slash stripped.
            },
        },
        Case {
            input: r#"//server/share/foo"#,
            expected: if TARGET_SUPPORTS_UNCS_AND_BACKSLASHES {
                "//server/share/foo" // UNC
            } else {
                // Redundant slash removed.
                "/server/share/foo"
            },
        },
        Case {
            input: r#"//server/share/foo/bar"#,
            expected: if TARGET_SUPPORTS_UNCS_AND_BACKSLASHES {
                "//server/share/foo/bar" // UNC
            } else {
                r#"/server/share/foo/bar"#
            }, // Redundant slash removed.
        },
        Case {
            // XXX: trailing slash stripped
            input: r#"//server/share/foo/bar/"#,
            expected: if TARGET_SUPPORTS_UNCS_AND_BACKSLASHES {
                "//server/share/foo/bar" // UNC
            } else {
                r#"/server/share/foo/bar"# // Redundant slash removed.
            },
        },
        Case {
            input: r#"//server\share"#,
            expected: if TARGET_SUPPORTS_UNCS_AND_BACKSLASHES {
                "//server/share/" // UNC with implied root
            } else {
                // Redundant slash removed. Backslash not interpreted as a separator.
                r#"/server\share"#
            },
        },
        Case {
            input: r#"//server\share/"#,
            expected: if TARGET_SUPPORTS_UNCS_AND_BACKSLASHES {
                "//server/share/" // UNC
            } else {
                // Redundant slash removed. Backslash not interpreted as a separator.
                // XXX: trailing slash stripped.
                r#"/server\share"#
            },
        },
        Case {
            input: r#"//server\share/foo"#,
            expected: if TARGET_SUPPORTS_UNCS_AND_BACKSLASHES {
                "//server/share/foo" // UNC
            } else {
                // Redundant slash removed. Backslash not interpreted as a separator.
                r#"/server\share/foo"#
            },
        },
        Case {
            input: r#"//server\share/foo/bar"#,
            expected: if TARGET_SUPPORTS_UNCS_AND_BACKSLASHES {
                "//server/share/foo/bar" // UNC
            } else {
                // Redundant slash removed. Backslash not interpreted as a separator.
                r#"/server\share/foo/bar"#
            },
        },
        Case {
            // XXX: trailing slash stripped
            input: r#"//server\share/foo/bar/"#,
            expected: if TARGET_SUPPORTS_UNCS_AND_BACKSLASHES {
                "//server/share/foo/bar" // UNC
            } else {
                // Redundant slash removed. Backslash not interpreted as a separator.
                r#"/server\share/foo/bar"#
            },
        },
        Case {
            input: r#"\\server\share"#,
            expected: if TARGET_SUPPORTS_UNCS_AND_BACKSLASHES {
                "//server/share/" // UNC with implied root
            } else {
                // Backslash not interpreted as a separator.
                r#"\\server\share"#
            },
        },
        Case {
            input: r#"\\server\share/"#,
            expected: if TARGET_SUPPORTS_UNCS_AND_BACKSLASHES {
                "//server/share/" // UNC
            } else {
                // Backslash not interpreted as a separator.
                // XXX: trailing slash stripped.
                r#"\\server\share"#
            },
        },
        Case {
            input: r#"\\server\share/foo"#,
            expected: if TARGET_SUPPORTS_UNCS_AND_BACKSLASHES {
                "//server/share/foo" // UNC
            } else {
                // Backslash not interpreted as a separator.
                r#"\\server\share/foo"#
            },
        },
        Case {
            input: r#"\\server\share/foo/bar"#,
            expected: if TARGET_SUPPORTS_UNCS_AND_BACKSLASHES {
                "//server/share/foo/bar" // UNC
            } else {
                // Backslash not interpreted as a separator.
                r#"\\server\share/foo/bar"#
            },
        },
        Case {
            // XXX: trailing slash stripped
            input: r#"\\server\share/foo/bar/"#,
            expected: if TARGET_SUPPORTS_UNCS_AND_BACKSLASHES {
                "//server/share/foo/bar" // UNC
            } else {
                // Backslash not interpreted as a separator.
                r#"\\server\share/foo/bar"#
            },
        },
        Case {
            input: r#"//server/share\"#,
            expected: if TARGET_SUPPORTS_UNCS_AND_BACKSLASHES {
                "//server/share/" // UNC
            } else {
                // Redundant slash removed. Backslash not interpreted as a separator.
                r#"/server/share\"#
            },
        },
        Case {
            input: r#"//server/share\foo"#,
            expected: if TARGET_SUPPORTS_UNCS_AND_BACKSLASHES {
                "//server/share/foo" // UNC
            } else {
                // Redundant slash removed. Backslash not interpreted as a separator.
                r#"/server/share\foo"#
            },
        },
        Case {
            input: r#"//server/share/foo\bar"#,
            expected: if TARGET_SUPPORTS_UNCS_AND_BACKSLASHES {
                "//server/share/foo/bar" // UNC
            } else {
                // Redundant slash removed. Backslash not interpreted as a separator.
                r#"/server/share/foo\bar"#
            },
        },
        Case {
            // XXX: trailing slash stripped
            input: r#"//server/share\foo/bar/"#,
            expected: if TARGET_SUPPORTS_UNCS_AND_BACKSLASHES {
                "//server/share/foo/bar"
            } else {
                // Redundant slash removed. Backslash not interpreted as a separator.
                r#"/server/share\foo/bar"#
            },
        },
        Case {
            input: r#"C:foo"#,
            expected: "C:foo",
        },
        Case {
            input: r#"C:\foo"#,
            expected: if TARGET_SUPPORTS_UNCS_AND_BACKSLASHES {
                "C:/foo"
            } else {
                r#"C:\foo"# // Backslash not interpreted as a separator.
            },
        },
        Case {
            input: r#"C:/foo"#,
            expected: "C:/foo",
        },
        Case {
            input: r#"a\b"#,
            expected: if TARGET_SUPPORTS_UNCS_AND_BACKSLASHES {
                "a/b"
            } else {
                r#"a\b"# // Backslash not interpreted as a separator.
            },
        },
        Case {
            input: r#"/a/b"#,
            expected: "/a/b",
        },
        Case {
            input: r#"\a\b"#,
            expected: if TARGET_SUPPORTS_UNCS_AND_BACKSLASHES {
                "/a/b"
            } else {
                r#"\a\b"# // Backslash not interpreted as a separator.
            },
        },
        Case {
            input: r#".\b"#,
            expected: if TARGET_SUPPORTS_UNCS_AND_BACKSLASHES {
                "./b"
            } else {
                r#".\b"# // Backslash not interpreted as a separator.
            },
        },
        Case {
            input: r#"../b"#,
            expected: "../b",
        },
        Case {
            input: r#"a/../b"#,
            expected: "a/../b",
        },
        Case {
            // XXX: Trailing slash is skipped.
            input: r#"a/./b/"#,
            expected: "a/b",
        },
    ];

    let failures = VALID_TEST_CASES
        .iter()
        .filter_map(|Case { input, expected }| {
            let actual = join_components_with_forward_slashes(Path::new(input)).unwrap();
            if actual == AsRef::<OsStr>::as_ref(expected) {
                None
            } else {
                Some((input, actual, expected))
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(failures, &[]);
}
