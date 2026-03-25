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

//! Symbol prefixing to prevent linking collisions with OpenSSL(-derivative)
//! libraries and with other versions of *ring*.

// Avoid `std::env` here. All configuration should be done through parameters.
use std::{fs, io::Write, path::Path};

/// Creates the necessary header files for symbol renaming.
///
/// For simplicity, both non-Nasm- and Nasm- style headers are always
/// generated, even though local non-packaged builds need only one of them.
pub fn generate_prefix_symbols_headers(
    out_dir: &Path,
    core_name_and_version: &str,
    symbols_to_rename: &[(&str, &str)],
    symbols_to_prefix: &[&str],
) -> Result<(), std::io::Error> {
    let prefix = &(String::from(core_name_and_version) + "_");

    generate_prefix_symbols_header(
        out_dir,
        "prefix_symbols.h",
        '#',
        None,
        prefix,
        symbols_to_rename,
        symbols_to_prefix,
    )?;

    generate_prefix_symbols_header(
        out_dir,
        "prefix_symbols_asm.h",
        '#',
        Some("#if defined(__APPLE__)"),
        prefix,
        symbols_to_rename,
        symbols_to_prefix,
    )?;

    generate_prefix_symbols_header(
        out_dir,
        "prefix_symbols_nasm.inc",
        '%',
        Some("%ifidn __OUTPUT_FORMAT__,win32"),
        prefix,
        symbols_to_rename,
        symbols_to_prefix,
    )?;

    Ok(())
}

fn generate_prefix_symbols_header(
    out_dir: &Path,
    filename: &str,
    pp: char,
    prefix_condition: Option<&str>,
    prefix: &str,
    symbols_to_rename: &[(&str, &str)],
    symbols_to_prefix: &[&str],
) -> Result<(), std::io::Error> {
    let dir = out_dir.join("ring_core_generated");
    fs::create_dir_all(&dir)?;

    let path = dir.join(filename);
    let mut file = fs::File::create(path)?;

    let filename_ident = filename.replace('.', "_").to_uppercase();
    writeln!(
        file,
        r#"
{pp}ifndef ring_core_generated_{filename_ident}
{pp}define ring_core_generated_{filename_ident}
"#
    )?;

    if let Some(prefix_condition) = prefix_condition {
        writeln!(file, "{prefix_condition}")?;
        writeln!(
            file,
            "{}",
            prefix_all_symbols(pp, "_", prefix, symbols_to_rename, symbols_to_prefix)
        )?;
        writeln!(file, "{pp}else")?;
    };
    writeln!(
        file,
        "{}",
        prefix_all_symbols(pp, "", prefix, symbols_to_rename, symbols_to_prefix)
    )?;
    if prefix_condition.is_some() {
        writeln!(file, "{pp}endif")?
    }

    writeln!(file, "{pp}endif")?;

    Ok(())
}

fn prefix_all_symbols(
    pp: char,
    prefix_prefix: &str,
    prefix: &str,
    symbols_to_rename: &[(&str, &str)],
    symbols_to_prefix: &[&str],
) -> String {
    let mut out = String::new();

    for (old, new) in symbols_to_rename {
        let line = format!("{pp}define {prefix_prefix}{old} {prefix_prefix}{new}\n");
        out += &line;
    }

    for symbol in symbols_to_prefix {
        let line = format!("{pp}define {prefix_prefix}{symbol} {prefix_prefix}{prefix}{symbol}\n");
        out += &line;
    }

    out
}
