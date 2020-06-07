use std::convert;
use std::fmt;
use std::path::PathBuf;
use std::result;

use peroxide_cryptsetup::context::Error as ContextError;
use peroxide_cryptsetup::db::Error as DatabaseError;
use peroxide_cryptsetup::device::{Disks, Error as DeviceError};
use peroxide_cryptsetup::input::Error as InputError;

use errno::Errno;
use uuid;

pub type Result<T> = result::Result<T, OperationError>;

#[derive(Debug)]
pub enum OperationError {
    ContextError(ContextError),
    NotFoundInDb(String),
    ValidationFailed(String),
}

impl fmt::Display for OperationError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            OperationError::ContextError(ref ce) => match ce {
                ContextError::DatabaseError(ref dbe) => match dbe {
                    DatabaseError::IoError(ref path, ref cause) => {
                        write!(fmt, "I/O error working on database {}: {}", path.display(), cause)
                    }
                    DatabaseError::SerialisationError(ref cause) => {
                        write!(fmt, "Unable to de/serialize database: {}", cause)
                    }
                },
                ContextError::DeviceAlreadyActivated(ref expl) => write!(fmt, "Device is already activated: {}", expl),
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
                ContextError::KeyInputError(ref kie) => match kie {
                    InputError::FeatureNotAvailable => write!(fmt, "Key input method is not available"),
                    InputError::IoError(ref cause) => write!(fmt, "Unknown I/O error during key input: {}", cause),
                    InputError::UnknownCryptoError => write!(fmt, "Unknown error occurred during crypto operation"),
                    #[cfg(feature = "yubikey")]
                    InputError::YubikeyError(ref cause) => write!(fmt, "Yubikey error: {}", cause),
                    #[cfg(feature = "pinentry")]
                    InputError::PinentryError(ref cause) => write!(fmt, "Pinentry error: {}", cause)
                },
                ContextError::VolumeNotFound(ref volume_id) => write!(fmt, "Could not find volume {}", volume_id),
            },
            OperationError::NotFoundInDb(ref cause) => write!(fmt, "Entry was not found in db: {}", cause),
            OperationError::ValidationFailed(ref cause) => write!(fmt, "Validation failed during operation: {}", cause),
        }
    }
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

/// Convert a user-input string which may be a device path _or_ a UUID into path
fn path_or_uuid_to_path(path_or_uuid: &str) -> Result<PathBuf> {
    if let Some(id) = uuid::Uuid::parse_str(path_or_uuid).ok() {
        Disks::disk_uuid_path(&id).map_err(From::from)
    } else {
        Ok(PathBuf::from(path_or_uuid))
    }
}

pub mod enroll;
pub mod list;
pub mod newdb;
pub mod open;
pub mod register;
