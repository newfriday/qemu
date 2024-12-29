// Copyright 2024, Linaro Limited
// Author(s): Manos Pitsidianakis <manos.pitsidianakis@linaro.org>
// SPDX-License-Identifier: GPL-2.0-or-later

//! Helper macros to declare migration state for device models.
//!
//! This module includes three families of macros:
//!
//! * [`vmstate_unused!`](crate::vmstate_unused) and
//!   [`vmstate_of!`](crate::vmstate_of), which are used to express the
//!   migration format for a struct.  This is based on the [`VMState`] trait,
//!   which is defined by all migrateable types.
//!
//! * helper macros to declare a device model state struct, in particular
//!   [`vmstate_subsections`](crate::vmstate_subsections) and
//!   [`vmstate_fields`](crate::vmstate_fields).
//!
//! * direct equivalents to the C macros declared in
//!   `include/migration/vmstate.h`. These are not type-safe and should not be
//!   used if the equivalent functionality is available with `vmstate_of!`.

use core::{marker::PhantomData, mem, ptr::NonNull};

use crate::bindings::VMStateFlags;
pub use crate::bindings::{VMStateDescription, VMStateField};

/// This macro is used to call a function with a generic argument bound
/// to the type of a field.  The function must take a
/// [`PhantomData`]`<T>` argument; `T` is the type of
/// field `$field` in the `$typ` type.
///
/// # Examples
///
/// ```
/// # use qemu_api::call_func_with_field;
/// # use core::marker::PhantomData;
/// const fn size_of_field<T>(_: PhantomData<T>) -> usize {
///     std::mem::size_of::<T>()
/// }
///
/// struct Foo {
///     x: u16,
/// };
/// // calls size_of_field::<u16>()
/// assert_eq!(call_func_with_field!(size_of_field, Foo, x), 2);
/// ```
#[macro_export]
macro_rules! call_func_with_field {
    // Based on the answer by user steffahn (Frank Steffahn) at
    // https://users.rust-lang.org/t/inferring-type-of-field/122857
    // and used under MIT license
    ($func:expr, $typ:ty, $($field:tt).+) => {
        $func(loop {
            #![allow(unreachable_code)]
            const fn phantom__<T>(_: &T) -> ::core::marker::PhantomData<T> { ::core::marker::PhantomData }
            // Unreachable code is exempt from checks on uninitialized values.
            // Use that trick to infer the type of this PhantomData.
            break ::core::marker::PhantomData;
            break phantom__(&{ let value__: $typ; value__.$($field).+ });
        })
    };
}

/// A trait for types that can be included in a device's migration stream.  It
/// provides the base contents of a `VMStateField` (minus the name and offset).
///
/// # Safety
///
/// The contents of this trait go straight into structs that are parsed by C
/// code and used to introspect into other structs.  Be careful.
pub unsafe trait VMState {
    /// The base contents of a `VMStateField` (minus the name and offset) for
    /// the type that is implementing the trait.
    const BASE: VMStateField;
}

/// Internal utility function to retrieve a type's `VMStateField`;
/// used by [`vmstate_of!`](crate::vmstate_of).
pub const fn vmstate_base<T: VMState>(_: PhantomData<T>) -> VMStateField {
    T::BASE
}

/// Return the `VMStateField` for a field of a struct.  The field must be
/// visible in the current scope.
///
/// In order to support other types, the trait `VMState` must be implemented
/// for them.
#[macro_export]
macro_rules! vmstate_of {
    ($struct_name:ty, $field_name:ident $(,)?) => {
        $crate::bindings::VMStateField {
            name: ::core::concat!(::core::stringify!($field_name), "\0")
                .as_bytes()
                .as_ptr() as *const ::std::os::raw::c_char,
            offset: $crate::offset_of!($struct_name, $field_name),
            // Compute most of the VMStateField from the type of the field.
            ..$crate::call_func_with_field!(
                $crate::vmstate::vmstate_base,
                $struct_name,
                $field_name
            )
        }
    };
}

impl VMStateFlags {
    const VMS_VARRAY_FLAGS: VMStateFlags = VMStateFlags(
        VMStateFlags::VMS_VARRAY_INT32.0
            | VMStateFlags::VMS_VARRAY_UINT8.0
            | VMStateFlags::VMS_VARRAY_UINT16.0
            | VMStateFlags::VMS_VARRAY_UINT32.0,
    );
}

// Add a couple builder-style methods to VMStateField, allowing
// easy derivation of VMStateField constants from other types.
impl VMStateField {
    #[must_use]
    pub const fn with_version_id(mut self, version_id: i32) -> Self {
        assert!(version_id >= 0);
        self.version_id = version_id;
        self
    }

    #[must_use]
    pub const fn with_array_flag(mut self, num: usize) -> Self {
        assert!(num <= 0x7FFF_FFFFusize);
        assert!((self.flags.0 & VMStateFlags::VMS_ARRAY.0) == 0);
        assert!((self.flags.0 & VMStateFlags::VMS_VARRAY_FLAGS.0) == 0);
        if (self.flags.0 & VMStateFlags::VMS_POINTER.0) != 0 {
            self.flags = VMStateFlags(self.flags.0 & !VMStateFlags::VMS_POINTER.0);
            self.flags = VMStateFlags(self.flags.0 | VMStateFlags::VMS_ARRAY_OF_POINTER.0);
        }
        self.flags = VMStateFlags(self.flags.0 & !VMStateFlags::VMS_SINGLE.0);
        self.flags = VMStateFlags(self.flags.0 | VMStateFlags::VMS_ARRAY.0);
        self.num = num as i32;
        self
    }

    #[must_use]
    pub const fn with_pointer_flag(mut self) -> Self {
        assert!((self.flags.0 & VMStateFlags::VMS_POINTER.0) == 0);
        self.flags = VMStateFlags(self.flags.0 | VMStateFlags::VMS_POINTER.0);
        self
    }
}

// Transparent wrappers: just use the internal type

macro_rules! impl_vmstate_transparent {
    ($type:ty where $base:tt: VMState $($where:tt)*) => {
        unsafe impl<$base> VMState for $type where $base: VMState $($where)* {
            const BASE: VMStateField = VMStateField {
                size: mem::size_of::<$type>(),
                ..<$base as VMState>::BASE
            };
        }
    };
}

impl_vmstate_transparent!(std::cell::Cell<T> where T: VMState);
impl_vmstate_transparent!(std::cell::UnsafeCell<T> where T: VMState);
impl_vmstate_transparent!(crate::cell::BqlCell<T> where T: VMState);
impl_vmstate_transparent!(crate::cell::BqlRefCell<T> where T: VMState);

// Pointer types using the underlying type's VMState plus VMS_POINTER
// Note that references are not supported, though references to cells
// could be allowed.

macro_rules! impl_vmstate_pointer {
    ($type:ty where $base:tt: VMState $($where:tt)*) => {
        unsafe impl<$base> VMState for $type where $base: VMState $($where)* {
            const BASE: VMStateField = <$base as VMState>::BASE.with_pointer_flag();
        }
    };
}

impl_vmstate_pointer!(*const T where T: VMState);
impl_vmstate_pointer!(*mut T where T: VMState);
impl_vmstate_pointer!(NonNull<T> where T: VMState);

// Unlike C pointers, Box is always non-null therefore there is no need
// to specify VMS_ALLOC.
impl_vmstate_pointer!(Box<T> where T: VMState);

// Arrays using the underlying type's VMState plus
// VMS_ARRAY/VMS_ARRAY_OF_POINTER

unsafe impl<T: VMState, const N: usize> VMState for [T; N] {
    const BASE: VMStateField = <T as VMState>::BASE.with_array_flag(N);
}

#[doc(alias = "VMSTATE_UNUSED_BUFFER")]
#[macro_export]
macro_rules! vmstate_unused_buffer {
    ($field_exists_fn:expr, $version_id:expr, $size:expr) => {{
        $crate::bindings::VMStateField {
            name: c_str!("unused").as_ptr(),
            err_hint: ::core::ptr::null(),
            offset: 0,
            size: $size,
            start: 0,
            num: 0,
            num_offset: 0,
            size_offset: 0,
            info: unsafe { ::core::ptr::addr_of!($crate::bindings::vmstate_info_unused_buffer) },
            flags: VMStateFlags::VMS_BUFFER,
            vmsd: ::core::ptr::null(),
            version_id: $version_id,
            struct_version_id: 0,
            field_exists: $field_exists_fn,
        }
    }};
}

#[doc(alias = "VMSTATE_UNUSED_V")]
#[macro_export]
macro_rules! vmstate_unused_v {
    ($version_id:expr, $size:expr) => {{
        $crate::vmstate_unused_buffer!(None, $version_id, $size)
    }};
}

#[doc(alias = "VMSTATE_UNUSED")]
#[macro_export]
macro_rules! vmstate_unused {
    ($size:expr) => {{
        $crate::vmstate_unused_v!(0, $size)
    }};
}

#[doc(alias = "VMSTATE_SINGLE_TEST")]
#[macro_export]
macro_rules! vmstate_single_test {
    ($field_name:ident, $struct_name:ty, $field_exists_fn:expr, $version_id:expr, $info:expr, $size:expr) => {{
        $crate::bindings::VMStateField {
            name: ::core::concat!(::core::stringify!($field_name), 0)
                .as_bytes()
                .as_ptr() as *const ::std::os::raw::c_char,
            err_hint: ::core::ptr::null(),
            offset: $crate::offset_of!($struct_name, $field_name),
            size: $size,
            start: 0,
            num: 0,
            num_offset: 0,
            size_offset: 0,
            info: unsafe { $info },
            flags: VMStateFlags::VMS_SINGLE,
            vmsd: ::core::ptr::null(),
            version_id: $version_id,
            struct_version_id: 0,
            field_exists: $field_exists_fn,
        }
    }};
}

#[doc(alias = "VMSTATE_SINGLE")]
#[macro_export]
macro_rules! vmstate_single {
    ($field_name:ident, $struct_name:ty, $version_id:expr, $info:expr, $size:expr) => {{
        $crate::vmstate_single_test!($field_name, $struct_name, None, $version_id, $info, $size)
    }};
}

#[doc(alias = "VMSTATE_UINT32_V")]
#[macro_export]
macro_rules! vmstate_uint32_v {
    ($field_name:ident, $struct_name:ty, $version_id:expr) => {{
        $crate::vmstate_single!(
            $field_name,
            $struct_name,
            $version_id,
            ::core::ptr::addr_of!($crate::bindings::vmstate_info_uint32),
            ::core::mem::size_of::<u32>()
        )
    }};
}

#[doc(alias = "VMSTATE_UINT32")]
#[macro_export]
macro_rules! vmstate_uint32 {
    ($field_name:ident, $struct_name:ty) => {{
        $crate::vmstate_uint32_v!($field_name, $struct_name, 0)
    }};
}

#[doc(alias = "VMSTATE_ARRAY")]
#[macro_export]
macro_rules! vmstate_array {
    ($field_name:ident, $struct_name:ty, $length:expr, $version_id:expr, $info:expr, $size:expr) => {{
        $crate::bindings::VMStateField {
            name: ::core::concat!(::core::stringify!($field_name), 0)
                .as_bytes()
                .as_ptr() as *const ::std::os::raw::c_char,
            err_hint: ::core::ptr::null(),
            offset: $crate::offset_of!($struct_name, $field_name),
            size: $size,
            start: 0,
            num: $length as _,
            num_offset: 0,
            size_offset: 0,
            info: unsafe { $info },
            flags: VMStateFlags::VMS_ARRAY,
            vmsd: ::core::ptr::null(),
            version_id: $version_id,
            struct_version_id: 0,
            field_exists: None,
        }
    }};
}

#[doc(alias = "VMSTATE_UINT32_ARRAY_V")]
#[macro_export]
macro_rules! vmstate_uint32_array_v {
    ($field_name:ident, $struct_name:ty, $length:expr, $version_id:expr) => {{
        $crate::vmstate_array!(
            $field_name,
            $struct_name,
            $length,
            $version_id,
            ::core::ptr::addr_of!($crate::bindings::vmstate_info_uint32),
            ::core::mem::size_of::<u32>()
        )
    }};
}

#[doc(alias = "VMSTATE_UINT32_ARRAY")]
#[macro_export]
macro_rules! vmstate_uint32_array {
    ($field_name:ident, $struct_name:ty, $length:expr) => {{
        $crate::vmstate_uint32_array_v!($field_name, $struct_name, $length, 0)
    }};
}

#[doc(alias = "VMSTATE_STRUCT_POINTER_V")]
#[macro_export]
macro_rules! vmstate_struct_pointer_v {
    ($field_name:ident, $struct_name:ty, $version_id:expr, $vmsd:expr, $type:ty) => {{
        $crate::bindings::VMStateField {
            name: ::core::concat!(::core::stringify!($field_name), 0)
                .as_bytes()
                .as_ptr() as *const ::std::os::raw::c_char,
            err_hint: ::core::ptr::null(),
            offset: $crate::offset_of!($struct_name, $field_name),
            size: ::core::mem::size_of::<*const $type>(),
            start: 0,
            num: 0,
            num_offset: 0,
            size_offset: 0,
            info: ::core::ptr::null(),
            flags: VMStateFlags(VMStateFlags::VMS_STRUCT.0 | VMStateFlags::VMS_POINTER.0),
            vmsd: unsafe { $vmsd },
            version_id: $version_id,
            struct_version_id: 0,
            field_exists: None,
        }
    }};
}

#[doc(alias = "VMSTATE_ARRAY_OF_POINTER")]
#[macro_export]
macro_rules! vmstate_array_of_pointer {
    ($field_name:ident, $struct_name:ty, $num:expr, $version_id:expr, $info:expr, $type:ty) => {{
        $crate::bindings::VMStateField {
            name: ::core::concat!(::core::stringify!($field_name), 0)
                .as_bytes()
                .as_ptr() as *const ::std::os::raw::c_char,
            version_id: $version_id,
            num: $num as _,
            info: unsafe { $info },
            size: ::core::mem::size_of::<*const $type>(),
            flags: VMStateFlags(VMStateFlags::VMS_ARRAY.0 | VMStateFlags::VMS_ARRAY_OF_POINTER.0),
            offset: $crate::offset_of!($struct_name, $field_name),
            err_hint: ::core::ptr::null(),
            start: 0,
            num_offset: 0,
            size_offset: 0,
            vmsd: ::core::ptr::null(),
            struct_version_id: 0,
            field_exists: None,
        }
    }};
}

#[doc(alias = "VMSTATE_ARRAY_OF_POINTER_TO_STRUCT")]
#[macro_export]
macro_rules! vmstate_array_of_pointer_to_struct {
    ($field_name:ident, $struct_name:ty, $num:expr, $version_id:expr, $vmsd:expr, $type:ty) => {{
        $crate::bindings::VMStateField {
            name: ::core::concat!(::core::stringify!($field_name), 0)
                .as_bytes()
                .as_ptr() as *const ::std::os::raw::c_char,
            version_id: $version_id,
            num: $num as _,
            vmsd: unsafe { $vmsd },
            size: ::core::mem::size_of::<*const $type>(),
            flags: VMStateFlags(
                VMStateFlags::VMS_ARRAY.0
                    | VMStateFlags::VMS_STRUCT.0
                    | VMStateFlags::VMS_ARRAY_OF_POINTER.0,
            ),
            offset: $crate::offset_of!($struct_name, $field_name),
            err_hint: ::core::ptr::null(),
            start: 0,
            num_offset: 0,
            size_offset: 0,
            vmsd: ::core::ptr::null(),
            struct_version_id: 0,
            field_exists: None,
        }
    }};
}

#[doc(alias = "VMSTATE_CLOCK_V")]
#[macro_export]
macro_rules! vmstate_clock_v {
    ($field_name:ident, $struct_name:ty, $version_id:expr) => {{
        $crate::vmstate_struct_pointer_v!(
            $field_name,
            $struct_name,
            $version_id,
            ::core::ptr::addr_of!($crate::bindings::vmstate_clock),
            $crate::bindings::Clock
        )
    }};
}

#[doc(alias = "VMSTATE_CLOCK")]
#[macro_export]
macro_rules! vmstate_clock {
    ($field_name:ident, $struct_name:ty) => {{
        $crate::vmstate_clock_v!($field_name, $struct_name, 0)
    }};
}

#[doc(alias = "VMSTATE_ARRAY_CLOCK_V")]
#[macro_export]
macro_rules! vmstate_array_clock_v {
    ($field_name:ident, $struct_name:ty, $num:expr, $version_id:expr) => {{
        $crate::vmstate_array_of_pointer_to_struct!(
            $field_name,
            $struct_name,
            $num,
            $version_id,
            ::core::ptr::addr_of!($crate::bindings::vmstate_clock),
            $crate::bindings::Clock
        )
    }};
}

#[doc(alias = "VMSTATE_ARRAY_CLOCK")]
#[macro_export]
macro_rules! vmstate_array_clock {
    ($field_name:ident, $struct_name:ty, $num:expr) => {{
        $crate::vmstate_array_clock_v!($field_name, $struct_name, $name, 0)
    }};
}

/// Helper macro to declare a list of
/// ([`VMStateField`](`crate::bindings::VMStateField`)) into a static and return
/// a pointer to the array of values it created.
#[macro_export]
macro_rules! vmstate_fields {
    ($($field:expr),*$(,)*) => {{
        static _FIELDS: &[$crate::bindings::VMStateField] = &[
            $($field),*,
            $crate::bindings::VMStateField {
                name: ::core::ptr::null(),
                err_hint: ::core::ptr::null(),
                offset: 0,
                size: 0,
                start: 0,
                num: 0,
                num_offset: 0,
                size_offset: 0,
                info: ::core::ptr::null(),
                flags: VMStateFlags::VMS_END,
                vmsd: ::core::ptr::null(),
                version_id: 0,
                struct_version_id: 0,
                field_exists: None,
            }
        ];
        _FIELDS.as_ptr()
    }}
}

/// A transparent wrapper type for the `subsections` field of
/// [`VMStateDescription`].
///
/// This is necessary to be able to declare subsection descriptions as statics,
/// because the only way to implement `Sync` for a foreign type (and `*const`
/// pointers are foreign types in Rust) is to create a wrapper struct and
/// `unsafe impl Sync` for it.
///
/// This struct is used in the
/// [`vm_state_subsections`](crate::vmstate_subsections) macro implementation.
#[repr(transparent)]
pub struct VMStateSubsectionsWrapper(pub &'static [*const crate::bindings::VMStateDescription]);

unsafe impl Sync for VMStateSubsectionsWrapper {}

/// Helper macro to declare a list of subsections ([`VMStateDescription`])
/// into a static and return a pointer to the array of pointers it created.
#[macro_export]
macro_rules! vmstate_subsections {
    ($($subsection:expr),*$(,)*) => {{
        static _SUBSECTIONS: $crate::vmstate::VMStateSubsectionsWrapper = $crate::vmstate::VMStateSubsectionsWrapper(&[
            $({
                static _SUBSECTION: $crate::bindings::VMStateDescription = $subsection;
                ::core::ptr::addr_of!(_SUBSECTION)
            }),*,
            ::core::ptr::null()
        ]);
        _SUBSECTIONS.0.as_ptr()
    }}
}
