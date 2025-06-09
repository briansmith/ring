macro_rules! match_target_word_bits {
    {
        64 => { $( $if_64:tt )* },
        32 => { $( $if_32:tt )* },
        $( _ => { $( $otherwise:tt )* } )?
    } => {
        cfg_if::cfg_if! {
            // Use 64-bit words on AArch64 ILP32 and x86-64 x32.
            if #[cfg(any(target_arch = "aarch64",
                         target_arch = "x86_64",
                         target_pointer_width = "64"))] {
                $( $if_64 )*
            } else if #[cfg(target_pointer_width = "32")] {
                $( $if_32 )*
            } else {
                $( $( $otherwise )* )?
            }
        }
    };

    {
        64 | 32 => { $( $if_64_or_32:item )* },
        $( _ => { $( $otherwise:tt )* } )?
    } => {
        cfg_if::cfg_if! {
            if #[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))] {
                $( $if_64_or_32 )*
            } else {
                $( $( $otherwise )* )?
            }
        }
    };
}
