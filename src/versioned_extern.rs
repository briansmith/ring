#[cfg(not(feature = "no_versioned_extern"))]
macro_rules! add_version_prefix {
    ($name:ident) => {
        concat!(
            "__RUST_RING_",
            env!("CARGO_PKG_VERSION_MAJOR"),
            "_",
            env!("CARGO_PKG_VERSION_MINOR"),
            "_",
            env!("CARGO_PKG_VERSION_PATCH"),
            "_",
            stringify!($name),
        )
    };
}

/// Prefixes imported extern "C" references with the versioned symbol prefix.
#[macro_export]
macro_rules! versioned_extern {
    // Function args w/ trailing comma
    (
        $(#[$($attr:tt)*])*
        $vis:vis
        fn $name:ident (
            $($var:ident: $typ:ty,)*
        ) $(-> $ret:ty)?;
        $($rest:tt)*
    ) => (
        versioned_extern!(
            [add_version_prefix!($name)]
            [$(#[$($attr)*])* $vis fn]
            $name
            [($($var: $typ,)*) $(-> $ret)?;]
            $($rest)*
        );
    );

    // Function args w/o trailing comma
    (
        $(#[$($attr:tt)*])*
        $vis:vis
        fn $name:ident (
            $($var:ident: $typ:ty),*
        ) $(-> $ret:ty)?;
        $($rest:tt)*
    ) => (
        versioned_extern!(
            [add_version_prefix!($name)]
            [$(#[$($attr)*])* $vis fn]
            $name
            [($($var: $typ,)*) $(-> $ret)?;]
            $($rest)*
        );
    );

    ($(#[$($attr:tt)*])* $vis:vis static $name:ident: $typ:ty; $($rest:tt)*) => (
        versioned_extern!(
            [add_version_prefix!($name)]
            [$(#[$($attr)*])* $vis static]
            $name
            [: $typ;]
            $($rest)*
        );
    );

    ($(#[$($attr:tt)*])* $vis:vis static mut $name:ident: $typ:ty; $($rest:tt)*) => (
        versioned_extern!(
            [add_version_prefix!($name)]
            [$(#[$($attr)*])* $vis static mut]
            $name
            [: $typ;]
            $($rest)*
        );
    );

    // Final output
    ([$v:expr] [$($pre:tt)+] $name:ident [$($post:tt)+] $($rest:tt)*) => (
        extern "C" {
            #[cfg(not(feature = "no_versioned_extern"))]
            #[link_name = $v]
            $($pre)+ $name $($post)+

            #[cfg(feature = "no_versioned_extern")]
            $($pre)+ $name $($post)+
        }

        // For simplicity, each item gets its own extern block
        versioned_extern! { $($rest)* }
    );

    // Base case for empty $rest
    () => ()
}
