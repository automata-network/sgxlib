# SGX Library

[![License](https://img.shields.io/badge/license-Apache-green.svg)](LICENSE)

`sgxlib` leverages the established [incubator-teaclave-sgx-sdk][teaclave] as its underlying SGX SDK, providing a stable and efficient foundation.

## Overview

`sgxlib` is a unified API designed to provide transparent use of `std` and `sgx` code. 
This library aims to simplify the integration of [Intel SGX][sgx] with your projects by offering a single interface to both standard and SGX-specific functionality.

## Usage

Cargo.toml
```toml
[features]
default = ["std"]

std = []
tstd = ["sgxlib/tstd"]

[dependencies]
sgxlib = { default-features = false }
```

src/lib.rs
```rust
#![cfg_attr(not(feature = "std"), no_std)]
#[cfg(feature = "tstd")]
#[macro_use]
extern crate sgxlib as std;

# in every files

use std::prelude::v1::*;
```

[sgx]: https://www.intel.com/content/www/us/en/developer/tools/software-guard-extensions/linux-overview.html
[teaclave]: https://github.com/apache/incubator-teaclave-sgx-sdk