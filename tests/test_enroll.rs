use std::path::{Path, PathBuf};

use expectest::prelude::*;

use cryptsetup_rs;
use cryptsetup_rs::{CryptDevice, Luks1CryptDevice};

use peroxide_cryptsetup::context::PeroxideDbReader;
use peroxide_cryptsetup::model::{DbEntry, DbEntryType, DbType, VolumeId};
use peroxide_cryptsetup::operation::{EnrollOperation, NewContainerParameters, PerformCryptOperation};

use support::*;

// TODO - create a test case for enrolment of a new disk with a new volume header
// TODO - create a test case for enrolment of a disk with an existing passphrase keyslot
// TODO - create a test case for enrolment of a disk with an existing backup keyslot

#[test]
fn test_enroll_new_device_with_keyfile() {
    setup();

    let temp_context = TemporaryDirContext::new(DbType::Backup);
    let device_file = temp_context.new_device_file().unwrap();

    let container_params = NewContainerParameters {
        cipher: "serpent-xts-plain".to_string(),
        hash: "sha256".to_string(),
        key_bits: 512,
    };
    let keyfile_content = [0xB, 0xA, 0xA, 0xA];
    let keyfile_temp_file = temp_context
        .write_keyfile(Some(Path::new("enroll_keyfile")), &keyfile_content)
        .unwrap();
    let keyfile_path = keyfile_temp_file.relative_to(&temp_context);

    let enroll_op = EnrollOperation::<TemporaryDirContext, TemporaryDirContext> {
        context: temp_context,
        entry_type: DbEntryType::Keyfile,
        new_container: Some(container_params),
        device_paths_or_uuids: vec![format!("{}", device_file.path().display())],
        iteration_ms: 10,
        keyfile: Some(keyfile_path.clone()),
        backup_context: None,
        name: Some("a_name".to_string()),
        yubikey_entry_type: None,
        yubikey_slot: None,
    };
    expect!(enroll_op.apply()).to(be_ok());

    // check we can load the crypt device
    let crypt_device = cryptsetup_rs::open(device_file.path()).unwrap().luks1().unwrap();

    // verify crypt device got setup correctly
    expect!(crypt_device.cipher()).to(be_equal_to("serpent"));
    expect!(crypt_device.cipher_mode()).to(be_equal_to("xts-plain"));
    expect!(crypt_device.volume_key_size()).to(be_equal_to(64));

    // verify the db got written correctly
    let db = enroll_op.context.open_peroxide_db().unwrap();
    expect!(db.entries.iter()).to(have_count(1));

    let expected_entry = DbEntry::KeyfileEntry {
        key_file: PathBuf::from("enroll_keyfile").join(keyfile_path.file_name().and_then(|n| n.to_str()).unwrap()),
        volume_id: VolumeId::new(Some("a_name".to_string()), crypt_device.uuid()),
    };

    expect!(db.entries.first()).to(be_some().value(&expected_entry));

    // TODO - try to verify the keyslot parameters but there's no api it seems
}
