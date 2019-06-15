#[cfg(not(feature = "boringssl_no_prefix"))]
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

/// Prefixes imported extern "C" references with the BoringSSL symbol prefix.
#[macro_export]
macro_rules! versioned_extern {
    // Function args w/ trailing comma
    (
        $(#[$($attr:tt)*])*
        fn $name:ident (
            $($var:ident: $typ:ty,)*
        ) $(-> $ret:ty)?;
        $($rest:tt)*
    ) => (
        versioned_extern!(
            [add_version_prefix!($name)]
            [$(#[$($attr)*])* fn]
            $name
            [($($var: $typ,)*) $(-> $ret)?;]
            $($rest)*
        );
    );

    // Function args w/o trailing comma
    (
        $(#[$($attr:tt)*])*
        fn $name:ident (
            $($var:ident: $typ:ty),*
        ) $(-> $ret:ty)?;
        $($rest:tt)*
    ) => (
        versioned_extern!(
            [add_version_prefix!($name)]
            [$(#[$($attr)*])* fn]
            $name
            [($($var: $typ,)*) $(-> $ret)?;]
            $($rest)*
        );
    );

    ($(#[$($attr:tt)*])* static $name:ident: $typ:ty; $($rest:tt)*) => (
        versioned_extern!(
            [add_version_prefix!($name)]
            [$(#[$($attr)*])* static]
            $name
            [: $typ;]
            $($rest)*
        );
    );

    ($(#[$($attr:tt)*])* static mut $name:ident: $typ:ty; $($rest:tt)*) => (
        versioned_extern!(
            [add_version_prefix!($name)]
            [$(#[$($attr)*])* static mut]
            $name
            [: $typ;]
            $($rest)*
        );
    );

    // Final output
    ([$v:expr] [$($pre:tt)+] $name:ident [$($post:tt)+] $($rest:tt)*) => (
        extern "C" {
            #[cfg(not(feature = "boringssl_no_prefix"))]
            #[link_name = $v]
            $($pre)+ $name $($post)+

            #[cfg(feature = "boringssl_no_prefix")]
            $($pre)+ $name $($post)+
        }

        // For simplicity, each item gets its own extern block
        versioned_extern! { $($rest)* }
    );

    // Base case for empty $rest
    () => ()
}

/// Prefixes exported extern "C" functions with the BoringSSL symbol prefix.
#[macro_export]
macro_rules! versioned_extern_def {
    ($(#[$($attr:tt)*])* $vis:vis unsafe fn $name:ident $($rest:tt)+) => (
        versioned_extern_def!(
            [add_version_prefix!($name)]
            [$(#[$($attr)*])* $vis unsafe extern "C" fn]
            $name
            [$($rest)+]
        );
    );

    ([$v:expr] [$($pre:tt)+] $name:ident [$($post:tt)+]) => (
        #[cfg(not(feature = "boringssl_no_prefix"))]
        #[link_name = $v]
        $($pre)+ $name $($post)+

        #[cfg(feature = "boringssl_no_prefix")]
        $($pre)+ $name $($post)+
    );
}
