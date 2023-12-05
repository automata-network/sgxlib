pub use sgxlib::sgx_types;
use sgxlib::sgx_types::*;
use sgxlib::sgx_urts::SgxEnclave;
use std::sync::Arc;

#[derive(Clone)]
pub struct Enclave {
    enclave: Arc<SgxEnclave>,
    filepath: String,
}

pub fn mrenclave(filepath: &str) -> Result<[u8; 32], String> {
    let data = std::fs::read(filepath).map_err(|err| format!("{:?}", err))?;
    let elf = goblin::elf::Elf::parse(&data).map_err(|err| format!("{:?}", err))?;
    let shstrndx = elf.header.e_shstrndx as usize;
    let string_table = &elf.section_headers[shstrndx];
    let section_name_strtab = &data
        [string_table.sh_offset as usize..(string_table.sh_offset + string_table.sh_size) as usize];

    for section in &elf.section_headers {
        let name_offset = section.sh_name as usize;
        let name = &section_name_strtab[name_offset..]
            .split(|&x| x == 0)
            .next()
            .ok_or("invalid section name".to_owned())?;
        if name == b".note.sgxmeta" {
            let offset = section.sh_offset as usize;
            let size = section.sh_size as usize;
            let section_data = &data[offset..offset + size];
            let mut mrenclave = [0_u8; 32];
            mrenclave.copy_from_slice(&section_data[1049..1081]);
            return Ok(mrenclave);
        }
    }

    return Err("mrenclave not found".to_owned());
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
        Self {
            enclave,
            filepath: name,
        }
    }

    pub fn mrenclave(&self) -> Result<[u8; 32], String> {
        mrenclave(&self.filepath)
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