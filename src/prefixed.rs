macro_rules! prefixed_extern {
    // Functions.
    {
        $(
            $( #[$meta:meta] )*
            $vis:vis fn $name:ident ( $( $arg_pat:ident : $arg_ty:ty ),* $(,)? )
            $( -> $ret_ty:ty )?;
        )+
    } => {
        extern "C" {
            $(
                prefixed_item! {
                    link_name
                    $name
                    {
                        $( #[$meta] )*
                        $vis fn $name ( $( $arg_pat : $arg_ty ),* ) $( -> $ret_ty )?;
                    }

                }
            )+
        }
    };

    // A global variable.
    {
        $( #[$meta:meta] )*
        $vis:vis static mut $name:ident: $typ:ty;
    } => {
        extern "C" {
            prefixed_item! {
                link_name
                $name
                {
                    $( #[$meta] )*
                    $vis static mut $name: $typ;
                }
            }
        }
    };
}

#[deprecated = "`#[export_name]` creates problems and we will stop doing it."]
#[cfg(not(any(
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "x86",
    target_arch = "x86_64"
)))]
macro_rules! prefixed_export {
    // A function.
    {
        $( #[$meta:meta] )*
        $vis:vis unsafe fn $name:ident ( $( $arg_pat:ident : $arg_ty:ty ),* $(,)? ) $body:block
    } => {
        prefixed_item! {
            export_name
            $name
            {
                $( #[$meta] )*
                $vis unsafe fn $name ( $( $arg_pat : $arg_ty ),* ) $body
            }
        }
    };
}

macro_rules! prefixed_item {
    // Calculate the prefixed name in a separate layer of macro expansion
    // because rustc won't currently accept a non-literal expression as
    // the value for `#[link_name = value]`.
    {
        $attr:ident
        $name:ident
        { $( $item:tt )+ }
    } => {
        prefixed_item! {
            $attr
            { concat!(env!("RING_CORE_PREFIX"), stringify!($name)) }
            { $( $item )+ }
        }
    };

    // Output the item.
    {
        $attr:ident
        { $prefixed_name:expr }
        { $( $item:tt )+ }
    } => {
        #[$attr = $prefixed_name]
        $( $item )+
    };
}
