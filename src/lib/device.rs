use std::convert::From;
use std::fs;
use std::io;
use std::io::ErrorKind;
use std::os::unix::prelude::OsStrExt;
use std::path::{Path, PathBuf};
use std::result;

use cryptsetup_rs;
pub use cryptsetup_rs::Keyslot;
use cryptsetup_rs::{luks_uuid, CryptDevice, Luks2CryptDevice, Luks2Token, Luks2TokenId, LuksCryptDevice};

use cryptsetup_rs::api::crypt_pbkdf_algo_type;
use errno;
use secstr::SecStr;
use uuid::Uuid;

#[derive(Debug)]
pub enum Error {
    /// Error that originates from underlying cryptsetup library
    CryptsetupError(errno::Errno),
    /// Error that originates from trying to read a device
    DeviceReadError(String),
    /// Error that originates from some other kind of IO
    IOError(::std::io::Error),
    /// Other error (unmatched)
    Other(String),
}

pub type Result<T> = result::Result<T, Error>;

impl From<cryptsetup_rs::Error> for Error {
    fn from(e: cryptsetup_rs::Error) -> Self {
        match e {
            cryptsetup_rs::Error::BlkidError(be) => Error::DeviceReadError(format!("{:?}", be)),
            cryptsetup_rs::Error::CryptsetupError(e) => Error::CryptsetupError(e),
            cryptsetup_rs::Error::IOError(ie) => Error::IOError(ie),
            other => Error::Other(other.to_string()),
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::IOError(e)
    }
}

// this assumes a udev-like /dev layout
const DISK_BY_UUID: &'static str = "/dev/disk/by-uuid";
const TOKEN_NAME: &'static str = "peroxide";
const SYSFS_VIRTUAL_BLOCK_DIR: &'static str = "/sys/devices/virtual/block";
const DEVFS_BLOCK_DIR: &'static str = "/dev/block";

const UUID_LENGTH: usize = 36;

// always use the argon2id variant
const LUKS2_PBKDF_TYPE: crypt_pbkdf_algo_type = crypt_pbkdf_algo_type::argon2id;

#[derive(Debug, Clone)]
pub enum FormatContainerParams {
    Luks1 {
        iteration_ms: u32,
        cipher: String,
        cipher_mode: String,
        hash: String,
        mk_bits: usize,
        uuid: Option<Uuid>,
    },
    Luks2 {
        cipher: String,
        cipher_mode: String,
        mk_bits: usize,
        hash: String,
        time_ms: u32,
        iterations: u32,
        max_memory_kb: u32,
        parallel_threads: u32,
        sector_size: Option<u32>,
        data_alignment: Option<u32>,
        save_label_in_header: bool,
        uuid: Option<Uuid>,
        label: Option<String>,
        token_id: Option<Luks2TokenId>,
    },
}

pub enum FormatResult {
    Luks1 {
        keyslot: Keyslot,
    },
    Luks2 {
        keyslot: Keyslot,
        token_id: Option<Luks2TokenId>,
    },
}

pub trait LuksVolumeOps {
    /// Activate the LUKS device with the given name
    fn luks_activate(&self, name: &str, key: &SecStr) -> Result<Keyslot>;

    /// Add new key to LUKS device (given another key)
    fn luks_add_key(
        &self,
        iteration_ms: usize,
        new_key: &SecStr,
        prev_key: &SecStr,
        params: &FormatContainerParams,
    ) -> Result<Keyslot>;

    // Format a new LUKS device with the given key
    fn luks_format_with_key(&self, key: &SecStr, params: &FormatContainerParams) -> Result<FormatResult>;

    /// Read the UUID of an existing LUKS1 device
    fn luks_uuid(&self) -> Result<Uuid>;
}

impl<P: AsRef<Path>> LuksVolumeOps for P {
    fn luks_activate(&self, name: &str, key: &SecStr) -> Result<Keyslot> {
        let keyslot = cryptsetup_rs::open(self)?.luks()?.either(
            |mut luks1| luks1.activate(name, key.unsecure()),
            |mut luks2| luks2.activate(name, key.unsecure()),
        )?;
        Ok(keyslot)
    }

    fn luks_add_key(
        &self,
        iteration_ms: usize,
        new_key: &SecStr,
        prev_key: &SecStr,
        params: &FormatContainerParams,
    ) -> Result<Keyslot> {
        // note: impl trait in closure would help: https://github.com/rust-lang/rust/issues/63065
        cryptsetup_rs::open(self)?.luks()?.either(
            |mut luks1| {
                luks1.set_iteration_time(iteration_ms as u64);
                luks1
                    .add_keyslot(new_key.unsecure(), Some(prev_key.unsecure()), None)
                    .map_err(From::from)
            },
            |mut luks2| {
                luks2.set_iteration_time(iteration_ms as u64);

                let token_id = match params {
                    FormatContainerParams::Luks2 {
                        hash,
                        time_ms,
                        iterations,
                        max_memory_kb,
                        parallel_threads,
                        token_id,
                        ..
                    } => {
                        // always use argon2id
                        luks2.set_pbkdf_params(
                            LUKS2_PBKDF_TYPE,
                            hash,
                            *time_ms,
                            *iterations,
                            *max_memory_kb,
                            *parallel_threads,
                        )?;
                        token_id
                    }
                    _ => &None,
                };

                let keyslot = luks2.add_keyslot(new_key.unsecure(), Some(prev_key.unsecure()), None)?;
                if let Some(token_id) = token_id {
                    luks2.assign_token_to_keyslot(*token_id, Some(keyslot))?;
                }

                Ok(keyslot)
            },
        )
    }

    fn luks_format_with_key(&self, key: &SecStr, params: &FormatContainerParams) -> Result<FormatResult> {
        match params {
            FormatContainerParams::Luks1 {
                iteration_ms,
                cipher,
                cipher_mode,
                hash,
                mk_bits,
                uuid,
            } => {
                let mut device = cryptsetup_rs::format(self)?
                    .iteration_time(*iteration_ms as u64)
                    .luks1(cipher, cipher_mode, hash, *mk_bits, uuid.as_ref())?;
                device.set_iteration_time(*iteration_ms as u64);
                let keyslot = device.add_keyslot(key.unsecure(), None, None)?;

                Ok(FormatResult::Luks1 { keyslot })
            }
            FormatContainerParams::Luks2 {
                cipher,
                cipher_mode,
                mk_bits,
                hash,
                time_ms,
                iterations,
                max_memory_kb,
                parallel_threads,
                sector_size,
                data_alignment,
                save_label_in_header: _save_label_in_header,
                uuid,
                label,
                token_id,
            } => {
                let mut format_builder = cryptsetup_rs::format(self)?
                    .luks2(
                        cipher,
                        cipher_mode,
                        *mk_bits,
                        uuid.as_ref(),
                        *data_alignment,
                        *sector_size,
                    )
                    .argon2id(hash, *time_ms, *iterations, *max_memory_kb, *parallel_threads);

                if let Some(label) = label {
                    format_builder = format_builder.label(label);
                }

                let mut device = format_builder.start()?;
                let key = device.add_keyslot(key.unsecure(), None, None)?;

                // always add a luks 2 token to the keyslot
                let token = Luks2Token {
                    type_: TOKEN_NAME.to_string(),
                    keyslots: vec![key.to_string()],
                    other: serde_json::Map::new(),
                };

                let tok = if let Some(token_id) = token_id {
                    device.add_token_with_id(&token, *token_id)?;
                    *token_id
                } else {
                    device.add_token(&token)?
                };

                Ok(FormatResult::Luks2 {
                    keyslot: key,
                    token_id: Some(tok),
                })
            }
        }
    }

    fn luks_uuid(&self) -> Result<Uuid> {
        cryptsetup_rs::luks_uuid(self.as_ref()).map_err(From::from)
    }
}

/// Information gathered about mapped disks from sysfs
#[derive(Debug)]
pub struct DmSetupDeviceInfo {
    /// dm-N name of the device
    pub dm_name: String,
    /// Mapped name of the device
    pub name: String,
    /// Underlying block path
    pub underlying: PathBuf,
    /// LUKS UUID
    pub underlying_uuid: Uuid,
}

pub struct Disks;

impl Disks {
    fn parse_uuid_from(path: &Path) -> Option<Uuid> {
        path.file_name()
            .and_then(|file_name| file_name.to_str())
            .and_then(|file_name| Uuid::parse_str(file_name).ok())
    }

    /// Return a list of all the disk UUIDs that are visible under `/dev/disk/by-uuid/`
    pub fn all_disk_uuids() -> Result<Vec<Uuid>> {
        // assume udev
        fs::read_dir(Path::new(DISK_BY_UUID))
            .and_then(|entries| {
                entries
                    .filter(Disks::has_full_uuid)
                    .map(|entry| {
                        entry.map(|e| e.path()).and_then(|p| {
                            Disks::parse_uuid_from(&p).ok_or(io::Error::new(ErrorKind::Other, "Uuid parsing failed"))
                        })
                    })
                    .collect()
            })
            .map_err(From::from)
    }

    /// Convert a UUID into a path under `/dev/disk/by-uuid/` if the disk with that UUID exists
    pub fn disk_uuid_path(uuid: &Uuid) -> Result<PathBuf> {
        let path = Path::new(DISK_BY_UUID).join(uuid.hyphenated().to_string());

        fs::symlink_metadata(&path)
            .and_then(|meta| {
                let ft = meta.file_type();
                if ft.is_file() || ft.is_symlink() {
                    Ok(path)
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("Disk path {} is not a file", path.display()),
                    ))
                }
            })
            .map_err(From::from)
    }

    /// Test whether a device name is in use already (i.e. it is actively mapped)
    pub fn is_device_active(name: &str) -> bool {
        debug!("checking device active {}", name);
        match cryptsetup_rs::api::status(name) {
            cryptsetup_rs::api::crypt_status_info::CRYPT_ACTIVE => true,
            cryptsetup_rs::api::crypt_status_info::CRYPT_BUSY => true,
            _ => false,
        }
    }

    // todo: consider adding this to the context + higher-level convenience methods
    /// Scan sysfs for active devices and return a list of found devices
    pub fn scan_sysfs_for_active_crypt_devices() -> Result<Vec<DmSetupDeviceInfo>> {
        let dm_paths = fs::read_dir(SYSFS_VIRTUAL_BLOCK_DIR)?
            .into_iter()
            .filter_map(|res| res.ok())
            .filter(|e| e.path().is_dir() && e.path().file_name().map_or(false, |c| c.as_bytes().starts_with(b"dm-")))
            .map(|e| e.path())
            .collect::<Vec<_>>();

        let mut res = vec![];
        for path in dm_paths {
            let name = fs::read_to_string(path.join("dm/name"))?;
            let slave_dirs = fs::read_dir(path.join("slaves"))?
                .into_iter()
                .filter_map(|res| res.ok())
                .filter(|e| e.path().is_symlink())
                .filter_map(|e| e.path().canonicalize().ok())
                .collect::<Vec<_>>();

            if slave_dirs.len() == 1 {
                let dev_name = fs::read_to_string(slave_dirs.get(0).unwrap().join("dev"))?;
                let dev_path = PathBuf::from(DEVFS_BLOCK_DIR)
                    .join(dev_name.trim_end())
                    .canonicalize()?;
                let luks_uuid = luks_uuid(&dev_path)?;

                res.push(DmSetupDeviceInfo {
                    dm_name: path.file_name().unwrap().to_string_lossy().to_string(),
                    name: name.trim_end().to_string(),
                    underlying: dev_path,
                    underlying_uuid: luks_uuid,
                })
            }
        }

        debug!("found sysfs mappings: {:?}", res);

        Ok(res)
    }

    // FAT32/NTFS disks do not have a UUID of the proper length - exclude them as they cannot be
    // LUKS disks
    fn has_full_uuid(e: &io::Result<fs::DirEntry>) -> bool {
        e.as_ref()
            .map(|entry| entry.path().file_name().unwrap().len() == UUID_LENGTH)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use expectest::prelude::*;

    #[test]
    fn test_all_disks_uuids_must_return_something() {
        let maybe_uuids = Disks::all_disk_uuids();
        expect!(maybe_uuids).to(be_ok());
    }
}
