#![deny(warnings)]

extern crate cryptsetup_rs;
extern crate env_logger;
extern crate tempdir;
extern crate uuid;

#[macro_use]
extern crate log;

#[macro_use]
extern crate expectest;

use std::process::Command;

use expectest::prelude::*;
use tempdir::TempDir;
use uuid::Uuid;

use cryptsetup_rs::device::*;

struct TestContext {
    dir: TempDir,
    name: String,
}

impl TestContext {
    fn new(name: String) -> TestContext {
        env_logger::init().unwrap();
        CryptDevice::enable_debug(true);
        let dir = tempdir::TempDir::new(&name).unwrap();
        TestContext {
            name: name,
            dir: dir,
        }
    }

    fn new_crypt_device(&self) -> CryptDevice {
        let crypt_file = self.dir.path().join(format!("{}.image", self.name));
        let dd_status = Command::new("dd")
                            .arg("if=/dev/zero")
                            .arg(format!("of={}", crypt_file.display()))
                            .arg("bs=1M")
                            .arg("count=10")
                            .status()
                            .unwrap();
        if !dd_status.success() {
            panic!("Failed to create disk image at {}", crypt_file.display());
        }

        let mut device = CryptDevice::new(crypt_file).unwrap();
        // use speedy rng
        device.set_rng_type(crypt_rng_type::CRYPT_RNG_URANDOM);
        device
    }
}

#[test]
fn test_create_new_luks_cryptdevice_no_errors() {
    let ctx = TestContext::new("new_luks_cryptdevice".to_string());
    let mut cd = ctx.new_crypt_device();
    let uuid = Uuid::new_v4();

    cd.set_iteration_time(42);
    expect!(cd.format_luks("aes", "xts-plain", "sha256", 256, Some(&uuid))).to(be_ok());
    expect!(cd.dump()).to(be_ok());

    expect!(cd.uuid()).to(be_some().value(uuid));
    expect!(cd.device_type()).to(be_some().value(crypt_device_type::LUKS1));
    expect!(cd.cipher()).to(be_some().value("aes"));
    expect!(cd.cipher_mode()).to(be_some().value("xts-plain"));
    expect!(cd.volume_key_size()).to(be_some().value(32));

    expect!(cd.add_keyslot(b"hello\0 world", None, None)).to(be_ok());
    // TODO verify keyslot was added correctly
}
