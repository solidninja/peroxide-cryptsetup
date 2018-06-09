use std::path::Path;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::result;
use std::time::Duration;

use uuid;

use cryptsetup_rs;

pub use cryptsetup_rs::Luks1CryptDeviceHandle as CryptDevice;

pub use io::KeyWrapper;
use io::{FileExtensions, Disks, TerminalPrompt};
use model::{DbLocation, PeroxideDb, YubikeySlot, YubikeyEntryType};


pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    KeyfileInputError { cause: io::Error },
    PasswordInputError { cause: io::Error },
    DatabaseIoError { path: PathBuf, cause: io::Error },
    DiskIoError {
        path: Option<PathBuf>,
        cause: io::Error,
    },
    YubikeyError { message: String },
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
        cryptsetup_rs::enable_debug(true);
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

pub trait ReaderContext: HasDbLocation + PeroxideDbReader + DiskSelector {}
pub trait WriterContext: ReaderContext + PeroxideDbWriter {}
pub trait InputContext: KeyfileInput + PasswordInput + YubikeyInput {}

impl ReaderContext for MainContext {}
impl WriterContext for MainContext {}
impl InputContext for MainContext {}
