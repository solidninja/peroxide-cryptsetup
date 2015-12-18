use std::path::Path;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::result;
use std::time::Duration;

use uuid;

use io::{KeyWrapper, FileExtensions, Disks, TerminalPrompt};
use model::{DbLocation, PeroxideDb, YubikeySlot, YubikeyEntryType};
use cryptsetup_rs::device::CryptDevice;

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    KeyfileInputError {
        cause: io::Error,
    },
    PasswordInputError {
        cause: io::Error,
    },
    DatabaseIoError {
        path: PathBuf,
        cause: io::Error,
    },
    DiskIoError {
        path: Option<PathBuf>,
        cause: io::Error,
    },
    YubikeyError {
        message: String,
    },
    UnknownCryptoError,
    FeatureNotAvailable,
}

pub trait HasDbLocation {
    fn db_location<'a>(&'a self) -> &'a DbLocation;
}

pub trait KeyfileInput: Sized {
    fn read_keyfile(&self, path: &Path) -> Result<KeyWrapper>;
}

pub trait PasswordInput: Sized {
    fn read_password(&self, prompt: &str) -> Result<KeyWrapper>;
}

pub trait YubikeyInput: PasswordInput {
    fn read_yubikey(&self, name: Option<&str>, uuid: &uuid::Uuid, slot: YubikeySlot, entry_type: YubikeyEntryType) -> Result<KeyWrapper>;
}

pub trait DiskSelector {
    fn all_disk_uuids(&self) -> Result<Vec<uuid::Uuid>>;
    fn disk_uuid_path(&self, uuid: &uuid::Uuid) -> Result<PathBuf>;
}

pub trait PeroxideDbReader: HasDbLocation {
    fn open_peroxide_db(&self) -> Result<PeroxideDb>;
}

pub trait PeroxideDbWriter: HasDbLocation {
    fn save_peroxide_db(&self, db: &PeroxideDb) -> Result<()>;
}

#[derive(Debug)]
pub struct MainContext {
    db_location: DbLocation,
    password_input_timeout: Option<Duration>,
}

impl MainContext {
    pub fn new(location: DbLocation) -> MainContext {
        MainContext {
            db_location: location,
            password_input_timeout: Some(Duration::new(30, 0)),
        }
    }

    pub fn trace_on() {
        CryptDevice::enable_debug(true);
    }
}

impl HasDbLocation for MainContext {
    fn db_location<'a>(&'a self) -> &'a DbLocation {
        &self.db_location
    }
}

impl KeyfileInput for MainContext {
    fn read_keyfile(&self, path: &Path) -> Result<KeyWrapper> {
        self.db_location
            .open_relative_path(path)
            .and_then(|mut file| KeyWrapper::read(&mut file))
            .map_err(|err| Error::KeyfileInputError { cause: err })
    }
}

impl PasswordInput for MainContext {
    fn read_password(&self, prompt: &str) -> Result<KeyWrapper> {
        TerminalPrompt::prompt_passphrase(prompt, self.password_input_timeout.as_ref())
            .map_err(|err| Error::PasswordInputError { cause: err })
    }
}

#[cfg(not(feature = "yubikey"))]
impl YubikeyInput for MainContext {
    #[allow(unused)]
    fn read_yubikey(&self, name: Option<&str>, uuid: &uuid::Uuid, slot: YubikeySlot, entry_type: YubikeyEntryType) -> Result<KeyWrapper> {
        Err(Error::FeatureNotAvailable)
    }
}

impl DiskSelector for MainContext {
    fn all_disk_uuids(&self) -> Result<Vec<uuid::Uuid>> {
        Disks::all_disk_uuids().map_err(|err| {
            Error::DiskIoError {
                path: None,
                cause: err,
            }
        })
    }

    fn disk_uuid_path(&self, uuid: &uuid::Uuid) -> Result<PathBuf> {
        Disks::disk_uuid_path(uuid).map_err(|err| {
            Error::DiskIoError {
                path: None,
                cause: err,
            }
        })
    }
}

impl PeroxideDbReader for MainContext {
    fn open_peroxide_db(&self) -> Result<PeroxideDb> {
        fs::File::open(&self.db_location.path)
            .and_then(|file| PeroxideDb::from(file))
            .map_err(|err| {
                Error::DatabaseIoError {
                    path: self.db_location.path.clone(),
                    cause: err,
                }
            })
    }
}

impl PeroxideDbWriter for MainContext {
    fn save_peroxide_db(&self, db: &PeroxideDb) -> Result<()> {
        fs::File::create(&self.db_location.path)
            .and_then(|mut file| db.save(&mut file))
            .map_err(|err| {
                Error::DatabaseIoError {
                    path: self.db_location.path.clone(),
                    cause: err,
                }
            })
    }
}

pub trait ReaderContext: HasDbLocation + PeroxideDbReader {}
pub trait WriterContext: ReaderContext + PeroxideDbWriter { }
pub trait InputContext: KeyfileInput + PasswordInput + YubikeyInput {}

impl ReaderContext for MainContext {}
impl WriterContext for MainContext {}
impl InputContext for MainContext {}

#[cfg(test)]
pub mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::io;

    use tempfile::NamedTempFile;
    use tempdir::TempDir;

    use super::*;
    use model::{DbType, DbLocation, PeroxideDb};
    use io::KeyWrapper;
    use io::tests::DbLocationWrapper;

    #[allow(dead_code)]
    pub struct TemporaryDirContext {
        main_context: MainContext,
        temp_dir: TempDir,
        db: PeroxideDb,
    }

    pub trait KeyfileOutput {
        fn write_keyfile(&self, subdir_opt: Option<&Path>, contents: &[u8]) -> io::Result<(PathBuf, NamedTempFile)>;
    }

    impl KeyfileOutput for TemporaryDirContext {
        fn write_keyfile(&self, subdir_opt: Option<&Path>, contents: &[u8]) -> io::Result<(PathBuf, NamedTempFile)> {
            let mut temp_file = match subdir_opt {
                Some(subdir) => {
                    let subdir_full = self.temp_dir.path().join(subdir);
                    try!(fs::create_dir(&subdir_full));
                    try!(NamedTempFile::new_in(&subdir_full))
                } 
                None => try!(NamedTempFile::new_in(self.temp_dir.path())),
            };
            try!(KeyWrapper::save_in(&mut temp_file, contents));

            let name_with_subdir = {
                let temp_filename = temp_file.path().file_name().and_then(|f| f.to_str()).unwrap();
                match subdir_opt {
                    Some(subdir) => subdir.join(temp_filename),
                    None => PathBuf::from(temp_filename),
                }
            };

            Ok((name_with_subdir, temp_file))
        }
    }

    // TODO: decide whether this is better in io
    impl TemporaryDirContext {
        pub fn new(db_type: DbType) -> TemporaryDirContext {
            let (peroxide_db, DbLocationWrapper(temp_dir, db_location)) = PeroxideDb::new_temporary_db(db_type);
            let main_context = MainContext {
                db_location: db_location,
                password_input_timeout: None,
            };
            main_context.save_peroxide_db(&peroxide_db).unwrap();
            TemporaryDirContext {
                main_context: main_context,
                temp_dir: temp_dir,
                db: peroxide_db,
            }
        }

        pub fn new_device_file(&self) -> io::Result<NamedTempFile> {
            let temp_file = try!(NamedTempFile::new_in(self.temp_dir.path()));
            try!(temp_file.set_len(150000000)); // 15 mb
            Ok(temp_file)
        }
    }

    impl HasDbLocation for TemporaryDirContext {
        fn db_location<'a>(&'a self) -> &'a DbLocation {
            self.main_context.db_location()
        }
    }

    impl PeroxideDbReader for TemporaryDirContext {
        fn open_peroxide_db(&self) -> Result<PeroxideDb> {
            self.main_context.open_peroxide_db()
        }
    }

    impl ReaderContext for TemporaryDirContext {}

    #[test]
    fn test_read_relative_keyfile_in_temp_dir() {
        let temp_context = TemporaryDirContext::new(DbType::Backup);
        let expected_content = vec![0xC, 0x0, 0xF, 0xF, 0xE, 0xE];
        let (keyfile_path, keyfile_temp_file) = temp_context.write_keyfile(Some(Path::new("test_subdir")), &expected_content).unwrap();

        let key_contents = temp_context.main_context.read_keyfile(&keyfile_path).unwrap();
        assert_eq!(key_contents.as_slice(), &expected_content as &[u8]);

        // not strictly necessary because destructor will probably run. Avoid the unused variable warning anyway
        keyfile_temp_file.close().unwrap();
    }
}
