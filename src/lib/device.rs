use std::convert::From;
use std::fs;
use std::io;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::result;

use cryptsetup_rs;
pub use cryptsetup_rs::Keyslot;
use cryptsetup_rs::{CryptDevice, LuksCryptDevice};

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
            other => Error::Other(other.to_string())
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
const DEV_MAPPER: &'static str = "/dev/mapper";

const UUID_LENGTH: usize = 36;

pub trait LuksVolumeOps {
    /// Activate the LUKS device with the given name
    fn luks_activate(&self, name: &str, key: &SecStr) -> Result<Keyslot>;

    /// Add new key to LUKS device (given another key)
    fn luks_add_key(&self, iteration_ms: usize, new_key: &SecStr, prev_key: &SecStr) -> Result<Keyslot>;

    /// Format a new LUKS device with the given key
    fn luks_format_with_key(
        &self,
        iteration_ms: usize,
        cipher: &str,
        cipher_mode: &str,
        hash: &str,
        mk_bits: usize,
        uuid_opt: Option<&Uuid>,
        key: &SecStr,
    ) -> Result<Keyslot>;

    /// Read the UUID of an existing LUKS1 device
    fn uuid(&self) -> Result<Uuid>;
}

impl<P: AsRef<Path>> LuksVolumeOps for P {
    fn luks_activate(&self, name: &str, key: &SecStr) -> Result<Keyslot> {
        let mut device = cryptsetup_rs::open(self)?.luks1()?;
        device.activate(name, key.unsecure()).map_err(From::from)
    }

    fn luks_add_key(&self, iteration_ms: usize, new_key: &SecStr, prev_key: &SecStr) -> Result<Keyslot> {
        let mut device = cryptsetup_rs::open(self)?.luks1()?;
        device.set_iteration_time(iteration_ms as u64);
        device
            .add_keyslot(new_key.unsecure(), Some(prev_key.unsecure()), None)
            .map_err(From::from)
    }

    fn luks_format_with_key(
        &self,
        iteration_ms: usize,
        cipher: &str,
        cipher_mode: &str,
        hash: &str,
        mk_bits: usize,
        uuid_opt: Option<&Uuid>,
        key: &SecStr,
    ) -> Result<Keyslot> {
        let mut device = cryptsetup_rs::format(self)?.iteration_time(iteration_ms as u64).luks1(
            cipher,
            cipher_mode,
            hash,
            mk_bits,
            uuid_opt,
        )?;
        device.set_iteration_time(iteration_ms as u64);
        device.add_keyslot(key.unsecure(), None, None).map_err(From::from)
    }

    fn uuid(&self) -> Result<Uuid> {
        cryptsetup_rs::luks_uuid(self.as_ref()).map_err(From::from)
    }
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
        let path = Path::new(DISK_BY_UUID).join(uuid.to_hyphenated().to_string());

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
    pub fn is_device_mapped(name: &str) -> bool {
        let path = Path::new(DEV_MAPPER).join(name);
        fs::metadata(&path).map(|meta| !meta.is_dir()).unwrap_or(false)
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
