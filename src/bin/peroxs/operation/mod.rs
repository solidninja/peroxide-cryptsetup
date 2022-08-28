use std::convert;
use std::error::Error;
use std::fmt;
use std::path::PathBuf;
use std::result;
use std::str::FromStr;

use errno::Errno;
use uuid;

use peroxide_cryptsetup::context::Error as ContextError;
use peroxide_cryptsetup::db::Error as DatabaseError;
use peroxide_cryptsetup::device::{Disks, Error as DeviceError};
use peroxide_cryptsetup::input::Error as InputError;

pub type Result<T> = result::Result<T, OperationError>;

#[derive(Debug)]
pub enum OperationError {
    ContextError(ContextError),
    ValidationFailed(String),
}

impl fmt::Display for OperationError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            OperationError::ContextError(ref ce) => match ce {
                ContextError::DatabaseError(ref dbe) => match dbe {
                    DatabaseError::DatabaseNotFound(ref path) => {
                        write!(fmt, "Database not found at {}", path.display())
                    }
                    DatabaseError::IoError(ref path, ref cause) => {
                        write!(fmt, "I/O error working on database {}: {}", path.display(), cause)
                    }
                    DatabaseError::SerialisationError(ref cause) => {
                        write!(fmt, "Unable to de/serialize database: {}", cause)
                    }
                },
                ContextError::DeviceAlreadyActivated(ref expl) => write!(fmt, "Device is already activated: {}", expl),
                ContextError::DeviceAlreadyFormatted(ref uuid) => {
                    write!(fmt, "Device with UUID={} is already formatted as LUKS", uuid)
                }
                ContextError::NotAllDisksAlreadyFormatted => {
                    write!(fmt, "Not all disks were formatted as LUKS containers")
                }
                ContextError::EntryAlreadyExists(ref uuid) => write!(
                    fmt,
                    "Entry with UUID={} already exists in database, and duplicate entries are not allowed",
                    uuid
                ),
                ContextError::DeviceError(ref de) => match de {
                    DeviceError::CryptsetupError(ref errno) => match errno {
                        Errno(1) => write!(fmt, "Wrong key for disk or permission denied"),
                        Errno(22) => write!(fmt, "Permission denied or invalid argument (cryptsetup)"),
                        _ => write!(fmt, "Cryptsetup failed with error: {}", errno),
                    },
                    DeviceError::DeviceReadError(ref cause) => write!(fmt, "Unable to read device: {}", cause),
                    DeviceError::IOError(ref cause) => write!(fmt, "Unknown I/O error working on device: {}", cause),
                    DeviceError::Other(ref expl) => write!(fmt, "Other error occurred: {}", expl),
                },
                ContextError::FeatureNotAvailable => write!(fmt, "This feature is not available"),
                ContextError::KeyInputError(ref kie) => kie.fmt(fmt),
                ContextError::VolumeNotFound(ref volume_id) => write!(fmt, "Could not find volume {}", volume_id),
                ContextError::DiskIdDuplicatesFound => write!(fmt, "Found duplicate disk IDs"),
                ContextError::DiskEntryNotFound(ref uuid) => {
                    write!(fmt, "Disk with UUID {} not found in database", uuid)
                }
            },
            OperationError::ValidationFailed(ref cause) => write!(fmt, "Validation failed during operation: {}", cause),
        }
    }
}

impl Error for OperationError {
    // todo: improve this
}

impl convert::From<ContextError> for OperationError {
    fn from(e: ContextError) -> OperationError {
        OperationError::ContextError(e)
    }
}

impl convert::From<DeviceError> for OperationError {
    fn from(e: DeviceError) -> Self {
        From::from(ContextError::DeviceError(e))
    }
}

impl convert::From<InputError> for OperationError {
    fn from(e: InputError) -> Self {
        From::from(ContextError::KeyInputError(e))
    }
}

#[derive(Debug)]
pub enum PathOrUuid {
    Path(PathBuf),
    Uuid(uuid::Uuid),
}

impl FromStr for PathOrUuid {
    type Err = OperationError;

    fn from_str(s: &str) -> Result<Self> {
        let uuid_opt = uuid::Uuid::from_str(s).ok();
        let path_opt = PathBuf::from_str(s).ok();

        if let Some(uuid) = uuid_opt {
            Ok(PathOrUuid::Uuid(uuid))
        } else if let Some(path) = path_opt {
            Ok(PathOrUuid::Path(path))
        } else {
            Err(OperationError::ValidationFailed(format!(
                "'{}' was not a path or uuid",
                s
            )))
        }
    }
}

impl PathOrUuid {
    /// Convert a UUID of a disk to a physical path
    pub fn to_path(&self) -> Result<PathBuf> {
        match self {
            PathOrUuid::Uuid(uuid) => Disks::disk_uuid_path(&uuid).map_err(From::from),
            PathOrUuid::Path(path) => Ok(path.clone()),
        }
    }
}

pub mod enroll;
pub mod list;
pub mod newdb;
pub mod open;
pub mod register;
