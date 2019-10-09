use std::path::{Path, PathBuf};
use std::result;
use std::time::Duration;

use cryptsetup_rs;

pub use cryptsetup_rs::Luks1CryptDeviceHandle as CryptDevice;

use secstr::SecStr;

use crate::db::{DbEntry, Error as DbError, PeroxideDb, VolumeId};
use crate::device::{Disks, Error as DeviceError, LuksVolumeOps};
use crate::input::{get_key_for, Error as InputError, KeyInputConfig};

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    DatabaseError(DbError),
    DeviceAlreadyActivated(String),
    DeviceError(DeviceError),
    FeatureNotAvailable,
    KeyInputError(InputError),
    VolumeNotFound(VolumeId),
}

impl From<DbError> for Error {
    fn from(e: DbError) -> Self {
        Error::DatabaseError(e)
    }
}

impl From<DeviceError> for Error {
    fn from(e: DeviceError) -> Self {
        Error::DeviceError(e)
    }
}

impl From<InputError> for Error {
    fn from(e: InputError) -> Self {
        Error::KeyInputError(e)
    }
}

pub trait Context {
    fn db_location(&self) -> &Path;
}

impl Context for MainContext {
    fn db_location(&self) -> &Path {
        self.db_path.as_ref()
    }
}

pub trait PeroxideDbOps {
    fn open_db(&self) -> Result<PeroxideDb>;
    fn save_db(&self, db: &PeroxideDb) -> Result<()>;
}

impl<C: Context> PeroxideDbOps for C {
    fn open_db(&self) -> Result<PeroxideDb> {
        PeroxideDb::open_at(self.db_location()).map_err(From::from)
    }

    fn save_db(&self, db: &PeroxideDb) -> Result<()> {
        db.save_to(self.db_location()).map_err(From::from)
    }
}

pub trait DeviceOps {
    /// Activate a disk and prompt for the key
    fn activate<P: AsRef<Path>>(
        &self,
        entry: &DbEntry,
        name_override: Option<String>,
        path_override: Option<P>,
    ) -> Result<String>;

    /// Active a disk with a given key
    fn activate_with_key<P: AsRef<Path>>(
        &self,
        entry: &DbEntry,
        key: &SecStr,
        name_override: Option<String>,
        path_override: Option<P>,
    ) -> Result<String>;

    /// Prompt for a key with a custom prompt
    fn prompt_key(&self, entry: &DbEntry, prompt: String) -> Result<SecStr>;
}

impl DeviceOps for MainContext {
    fn activate<P: AsRef<Path>>(
        &self,
        entry: &DbEntry,
        name_override: Option<String>,
        path_override: Option<P>,
    ) -> Result<String> {
        let key = get_key_for(
            entry,
            &standard_prompt,
            &self.key_input_config,
            &self.db_path.parent().expect("parent path"),
        )?;
        self.activate_with_key(entry, &key, name_override, path_override)
    }

    fn activate_with_key<P: AsRef<Path>>(
        &self,
        entry: &DbEntry,
        key: &SecStr,
        name_override: Option<String>,
        path_override: Option<P>,
    ) -> Result<String> {
        let name = name_override
            .or(entry.volume_id().name.clone())
            .unwrap_or_else(|| format!("uuid_{}", entry.volume_id().uuid()));

        if Disks::is_device_mapped(name.as_str()) {
            return Err(Error::DeviceAlreadyActivated(name));
        }

        let default_path = Disks::disk_uuid_path(entry.volume_id().uuid()).ok();
        // lim count(as_ref) -> ∞
        let path_opt = path_override
            .as_ref()
            .map(|p| p.as_ref())
            .or(default_path.as_ref().map(|p| p.as_ref()));

        if let Some(device_path) = path_opt {
            device_path
                .luks_activate(name.as_str(), key)
                .map(move |_| name)
                .map_err(From::from)
        } else {
            Err(Error::VolumeNotFound(entry.volume_id().clone()))
        }
    }

    fn prompt_key(&self, entry: &DbEntry, prompt: String) -> Result<SecStr> {
        get_key_for(
            entry,
            &move |_| prompt.clone(),
            &self.key_input_config,
            &self.db_path.parent().expect("parent path"),
        ).map_err(From::from)
    }
}

pub trait DatabaseOps {
    /// Given a disk path, find the corresponding db entry
    fn find_entry_for_disk_path<P: AsRef<Path>>(&self, path: P) -> Option<&DbEntry>;
}

impl DatabaseOps for PeroxideDb {
    fn find_entry_for_disk_path<P: AsRef<Path>>(&self, path: P) -> Option<&DbEntry> {
        path.uuid()
            .ok()
            .and_then(|disk_uuid| self.entries.iter().find(|e| e.volume_id().uuid() == &disk_uuid))
    }
}

pub fn standard_prompt(volume_id: &VolumeId) -> String {
    format!("Please enter key for {}: ", volume_id)
}

#[derive(Debug)]
pub struct MainContext {
    pub db_path: PathBuf,
    pub key_input_config: KeyInputConfig,
}

impl MainContext {
    pub fn new(db_path: PathBuf) -> MainContext {
        MainContext {
            db_path,
            key_input_config: KeyInputConfig {
                password_input_timeout: Some(Duration::new(30, 0)),
            },
        }
    }

    pub fn trace_on() {
        cryptsetup_rs::enable_debug(true);
    }
}
