#[cfg_attr(not(target_pointer_width = "64"), path = "soft/fixslice32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "soft/fixslice64.rs")]
pub(crate) mod fixslice;
