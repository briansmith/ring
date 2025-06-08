macro_rules! match_target_word_bits {
    {
        64 => { $( $if_64:item )* },
        32 => { $( $if_32:item )* },
    } => {
        cfg_if::cfg_if! {
            if #[cfg(target_pointer_width = "64")] {
                $( $if_64 )*
            } else if #[cfg(target_pointer_width = "32")] {
                $( $if_32 )*
            }
        }
    };

    {
        64 | 32 => { $( $if_64_or_32:item )* },
    } => {
        cfg_if::cfg_if! {
            if #[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))] {
                $( $if_64_or_32 )*
            }
        }
    };
}
