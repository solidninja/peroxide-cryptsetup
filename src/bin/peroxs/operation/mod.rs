use std::path::PathBuf;
use std::result;
use std::str::FromStr;

use snafu::{prelude::*, Backtrace};
use uuid;

use peroxide_cryptsetup::context::Error as ContextError;
use peroxide_cryptsetup::device::{Disks, Error as DeviceError};

#[derive(Debug, Snafu)]
pub enum OperationError {
    ContextError {
        #[snafu(backtrace)]
        source: ContextError,
    },
    DeviceError {
        #[snafu(backtrace)]
        source: DeviceError,
    },
    #[snafu(display("Validation failed: {message}"))]
    ValidationError { message: String, backtrace: Backtrace },
}

pub type Result<T> = result::Result<T, OperationError>;

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
            Err(ValidationSnafu {
                message: format!("'{}' was not a path or uuid", s),
            }
            .build())
        }
    }
}

impl PathOrUuid {
    /// Convert a UUID of a disk to a physical path
    pub fn to_path(&self) -> Result<PathBuf> {
        match self {
            PathOrUuid::Uuid(uuid) => Disks::disk_uuid_path(&uuid).context(DeviceSnafu),
            PathOrUuid::Path(path) => Ok(path.clone()),
        }
    }
}

pub mod enroll;
pub mod list;
pub mod newdb;
pub mod open;
pub mod register;
