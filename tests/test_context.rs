use std::path::Path;

use peroxide_cryptsetup::model::DbType;
use peroxide_cryptsetup::context::KeyfileInput;

use support::*;

#[test]
fn test_read_relative_keyfile_in_temp_subdir() {
    setup();

    let temp_context = TemporaryDirContext::new(DbType::Backup);
    let expected_content = [0xC, 0x0, 0xF, 0xF, 0xE, 0xE];
    let keyfile_temp_file = temp_context.write_keyfile(Some(Path::new("test_subdir")), &expected_content).unwrap();
    let keyfile_path = keyfile_temp_file.relative_to(&temp_context);

    let key_contents = temp_context.read_keyfile(&keyfile_path).unwrap();
    assert_eq!(key_contents.as_slice(), &expected_content);
}

#[test]
fn test_read_relative_keyfile_in_temp_dir() {
    setup();

    let temp_context = TemporaryDirContext::new(DbType::Backup);
    let expected_content = [0xC, 0x0, 0xF, 0xF, 0xE, 0xE];
    let keyfile_temp_file = temp_context.write_keyfile(None, &expected_content).unwrap();
    let keyfile_path = keyfile_temp_file.relative_to(&temp_context);

    let key_contents = temp_context.read_keyfile(&keyfile_path).unwrap();
    assert_eq!(key_contents.as_slice(), &expected_content);
}

// TODO - write tests for the relativisation of paths
// TODO - how to test that secret key is gone from memory instead of relying on rust zeroing it out for us
// TODO - write test for disk path
