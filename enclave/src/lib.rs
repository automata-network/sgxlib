pub use sgxlib::sgx_types;
use sgxlib::sgx_types::*;
use sgxlib::sgx_urts::SgxEnclave;
use std::sync::Arc;

#[derive(Clone)]
pub struct Enclave {
    enclave: Arc<SgxEnclave>,
}

impl Enclave {
    pub fn new(fname: &str) -> Self {
        let name = match std::env::current_exe() {
            Ok(mut path) => {
                path.pop();
                format!("{}/{}", path.to_str().unwrap(), fname)
            }
            Err(_) => format!("{}", fname),
        };
        let name = format!("{}.signed.so", name);
        let enclave = Arc::new(Self::_init_enclave(&name));
        Self { enclave }
    }

    pub fn eid(&self) -> sgx_enclave_id_t {
        self.enclave.geteid()
    }

    fn _init_enclave(enclave_name: &str) -> SgxEnclave {
        let mut launch_token: sgx_launch_token_t = [0; 1024];
        let mut launch_token_updated: i32 = 0;

        let debug = 0;
        let mut misc_attr = sgx_misc_attribute_t {
            secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
            misc_select: 0,
        };
        let result = SgxEnclave::create(
            enclave_name,
            debug,
            &mut launch_token,
            &mut launch_token_updated,
            &mut misc_attr,
        )
        .expect("Error loading enclave!");
        result
    }
}

#[macro_export]
macro_rules! unsafe_ecall {
    ($enclave:expr, $func_name:ident ($($args:expr),*)) => {
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

pub fn to_result(s: sgx_types::sgx_status_t) -> Result<(), sgx_types::sgx_status_t> {
    match s {
        sgx_types::sgx_status_t::SGX_SUCCESS => Ok(()),
        other => Err(other),
    }
}

pub fn get_extended_epid_gid() -> u32 {
    let mut extended_epid_gid = 0u32;
    unsafe {
        to_result(sgx_types::sgx_get_extended_epid_group_id(
            &mut extended_epid_gid,
        ))
        .unwrap()
    }
    extended_epid_gid
}
