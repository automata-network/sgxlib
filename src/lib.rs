#![cfg_attr(not(feature = "std"), no_std)]

#[macro_export]
macro_rules! lib {
    () => {
        #[cfg(feature = "tstd")]
        extern crate sgxlib as std;
        use std::prelude::v1::*;
    };
}

#[cfg(feature = "tstd")]
pub use sgx_tstd::*;
#[cfg(feature = "tstd")]
pub mod sync {
    pub use sgx_tstd::sync::SgxMutex as Mutex;
    pub use sgx_tstd::sync::SgxRwLock as RwLock;
    pub use sgx_tstd::sync::*;
}

#[cfg(feature = "types")]
pub use sgx_types;

#[cfg(feature = "tstd")]
pub use sgx_tcrypto as crypto;
#[cfg(all(feature = "sgx", not(feature = "std"), not(feature = "tcrypto")))]
pub use sgx_ucrypto as crypto;

#[cfg(feature = "urts")]
pub use sgx_urts;

#[cfg(feature = "trts")]
pub use sgx_trts;

#[cfg(feature = "libc")]
pub use sgx_libc;

#[cfg(feature = "tkey_exchange")]
pub use sgx_tkey_exchange;

#[cfg(feature = "types")]
#[macro_export]
macro_rules! unsafe_ecall {
    ($enclave:tt, $func_name:ident ($($args:expr),*)) => {
        unsafe {
            use $crate::sgx_types::sgx_status_t;
            let mut ret = sgx_status_t::SGX_SUCCESS;
            let ecall_ret = $func_name($enclave, &mut ret, $($args),*);
            match $crate::to_result(ecall_ret) {
                Ok(_) => $crate::to_result(ret),
                Err(err) => Err(err),
            }
        }
    }
}

#[cfg(feature = "types")]
#[macro_export]
macro_rules! unsafe_ocall {
    ($func_name:ident ($($args:expr),* $(,)*)) => {
        unsafe {
            use $crate::sgx_types::sgx_status_t;
            let mut ret = sgx_status_t::SGX_SUCCESS;
            $func_name(&mut ret, $($args),*);
            $crate::to_result(ret)
        }
    }
}

#[cfg(feature = "types")]
pub fn to_result(s: sgx_types::sgx_status_t) -> Result<(), sgx_types::sgx_status_t> {
    match s {
        sgx_types::sgx_status_t::SGX_SUCCESS => Ok(()),
        other => Err(other),
    }
}

pub fn get_extended_epid_gid() -> u32 {
    return 0;
    // #[cfg(not(feature = "types"))]
    // {
    //     panic!("features sgxlib[types] is not enabled");
    // }
    // #[cfg(feature = "types")]
    // {
    //     let mut extended_epid_gid = 0u32;
    //     unsafe {
    //         to_result(sgx_types::sgx_get_extended_epid_group_id(
    //             &mut extended_epid_gid,
    //         ))
    //         .unwrap()
    //     }
    //     extended_epid_gid
    // }
}
