// SPDX-License-Identifier: Apache-2.0

use crate::*;
use crate::intel::LinkType;
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct Metadata {
    geode: Config,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct Config {
    enclaves: Vec<String>,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct Build {
    manifest_dir: PathBuf,
    out_dir: PathBuf,
    enclaves: Vec<enclave::Build>,
}

impl Build {
    pub fn new() -> Build {
        let manifest_dir = Path::new(&CARGO_MANIFEST_DIR.to_string()).to_path_buf();
        Build::from_manifest(&manifest_dir)
    }

    pub fn from_manifest(manifest_dir: &PathBuf) -> Build {
        let manifest =
            Manifest::<Metadata>::from_path_with_metadata(manifest_dir.join("Cargo.toml")).unwrap();
        let out_dir = Path::new(&OUT_DIR.to_string()).to_path_buf();
        let enclaves = manifest.package.map_or(vec![], |p| {
            p.metadata.map_or(vec![], |m| {
                m.geode
                    .enclaves
                    .iter()
                    .map(|dir| {
                        enclave::Build::from_manifest(&manifest_dir.join(dir), Some(&out_dir))
                    })
                    .collect()
            })
        });

        Build {
            manifest_dir: manifest_dir.to_path_buf(),
            out_dir,
            enclaves,
        }
    }

    pub fn build(&self, ty: LinkType) {
        let mut ecall_externs = vec![];

        let _ = &self.enclaves.iter().for_each(|e| {
            e.build_crate();
            e.generate_interfaces();
            ecall_externs.extend(e.collect_ecall_extern());
            e.build_enclave();
            e.sign_enclave();
            e.build_untrusted();

            let enclave_path = e.signed_enclave_path();
            let target_path = self.out_dir.join(enclave_path.file_name().unwrap());

            // FIXME: get the path heuristically instead of hard-coding
            let target_path2 = self
                .out_dir
                .join("../../../")
                .join(enclave_path.file_name().unwrap());

            fs::copy(enclave_path, &target_path).unwrap();
            fs::copy(enclave_path, &target_path2).unwrap();
        });

        generate_extern_proxy(&self.out_dir.join("ecall.rs"), &ecall_externs);

        intel::sgx_sdk_cargo_metadata(ty);
    }

    pub fn build_signing_material(&self) {
        let _ = &self.enclaves.iter().for_each(|e| {
            e.build_crate();
            e.generate_interfaces();
            e.build_enclave();
            e.generate_enclave_material_data();

            let enclave_path = e.signing_material_data_path();
            let target_path = self.out_dir.join(enclave_path.file_name().unwrap());

            // FIXME: get the path heuristically instead of hard-coding
            let target_path2 = self
                .out_dir
                .join("../../../")
                .join(enclave_path.file_name().unwrap());

            fs::copy(enclave_path, &target_path).unwrap();
            fs::copy(enclave_path, &target_path2).unwrap();
        });
    }

    pub fn build_sign_with_pem(&self) -> HashMap<String, PathBuf> {
        let mut signatures: HashMap<String, PathBuf> = HashMap::new();

        let _ = &self.enclaves.iter().for_each(|e| {
            let material_path = e.signing_material_data_path();
            let material_src_path = self.out_dir.join(material_path.file_name().unwrap());
            let key_path = Path::new(&ENCLAVE_SIGNING_KEY.to_string()).to_path_buf();
            let signature_path = self.out_dir.join("signature.hex");
            subprocess(
                "openssl",
                &[
                    "dgst",
                    "-sha256",
                    "-out",
                    &signature_path.to_str().unwrap(),
                    "-sign",
                    &key_path.to_str().unwrap(),
                    "-keyform",
                    "PEM",
                    &material_src_path.to_str().unwrap(),
                ],
                None,
            );
            signatures.insert(e.crate_name().clone(), signature_path);
        });

        signatures
    }

    pub fn build_signed_material(&self, pubkey_path: &PathBuf, signatures: &HashMap<String, PathBuf>, ty: LinkType) {
        let mut ecall_externs = vec![];

        let _ = &self.enclaves.iter().for_each(|e| {
            ecall_externs.extend(e.collect_ecall_extern());
            e.build_enclave();
            // FIXME: raise error when signature not found
            let signature_path = signatures.get(e.crate_name()).unwrap();
            e.sign_generated_enclave_data(pubkey_path, signature_path);
            e.build_untrusted();

            let enclave_path = e.signed_enclave_path();
            let target_path = self.out_dir.join(enclave_path.file_name().unwrap());

            // FIXME: get the path heuristically instead of hard-coding
            let target_path2 = self
                .out_dir
                .join("../../../")
                .join(enclave_path.file_name().unwrap());

            fs::copy(enclave_path, &target_path).unwrap();
            fs::copy(enclave_path, &target_path2).unwrap();
        });

        generate_extern_proxy(&self.out_dir.join("ecall.rs"), &ecall_externs);

        intel::sgx_sdk_cargo_metadata(ty);
    }
}
