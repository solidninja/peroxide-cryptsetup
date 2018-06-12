use std::collections::HashMap;
use std::convert;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::result;
use std::str::FromStr;

use cryptsetup_rs;
use uuid;

use context;
use model::{DbEntryType, VolumeId, YubikeyEntryType, YubikeySlot};

trait LuksDevice: cryptsetup_rs::CryptDevice + cryptsetup_rs::Luks1CryptDevice {}

impl LuksDevice for cryptsetup_rs::Luks1CryptDeviceHandle {}

pub type Result<T> = result::Result<T, OperationError>;

#[derive(Debug)]
pub struct NewDatabaseOperation<Context: context::WriterContext> {
    pub context: Context,
}

#[derive(Debug)]
pub struct ListOperation<Context: context::ReaderContext + context::DiskSelector> {
    pub context: Context,
    pub only_available: bool,
}

#[derive(Debug)]
pub struct OpenOperation<Context>
where
    Context: context::ReaderContext + context::InputContext,
{
    pub context: Context,
    pub device_paths_or_uuids: Vec<String>,
    pub name: Option<String>,
}

#[derive(Debug)]
pub struct RegisterOperation<Context>
where
    Context: context::WriterContext,
{
    pub context: Context,
    pub entry_type: DbEntryType,
    pub device_paths_or_uuids: Vec<String>,
    pub keyfile: Option<PathBuf>,
    pub name: Option<String>,
}

#[derive(Debug)]
pub struct EnrollOperation<Context, BackupContext>
where
    Context: context::WriterContext + context::InputContext,
    BackupContext: context::ReaderContext + context::InputContext,
{
    pub context: Context,
    pub entry_type: DbEntryType,
    pub new_container: Option<NewContainerParameters>,
    pub device_paths_or_uuids: Vec<String>,
    pub iteration_ms: usize,
    pub keyfile: Option<PathBuf>,
    pub backup_context: Option<BackupContext>,
    pub name: Option<String>,
    pub yubikey_slot: Option<YubikeySlot>,
    pub yubikey_entry_type: Option<YubikeyEntryType>,
}

pub trait PerformCryptOperation {
    fn apply(&self) -> Result<()>;
}

#[derive(Debug)]
pub enum CryptOperation {
    Enroll(EnrollOperation<context::MainContext, context::MainContext>),
    NewDatabase(NewDatabaseOperation<context::MainContext>),
    List(ListOperation<context::MainContext>),
    Open(OpenOperation<context::MainContext>),
    Register(RegisterOperation<context::MainContext>),
}

impl CryptOperation {
    pub fn perform(self) -> Result<()> {
        // TODO Once https://github.com/rust-lang/rfcs/issues/754 is available rewrite this
        match self {
            CryptOperation::Enroll(enroll_op) => enroll_op.apply(),
            CryptOperation::List(list_op) => list_op.apply(),
            CryptOperation::NewDatabase(newdb_op) => newdb_op.apply(),
            CryptOperation::Open(open_op) => open_op.apply(),
            CryptOperation::Register(register_op) => register_op.apply(),
        }
    }
}

#[derive(Debug)]
pub struct NewContainerParameters {
    pub cipher: String,
    pub hash: String,
    pub key_bits: usize,
}

#[derive(Debug)]
pub enum OperationError {
    Action(Option<String>, io::Error),
    InvalidOperation(String),
    ValidationFailed(String),
    CryptOperationFailed(PathBuf, String),
    BackupDbOpenFailed,
    DbOpenFailed,
    DbSaveFailed,
    NotFoundInDb(String),
    BugExplanation(String),
    FeatureNotAvailable,
    UnknownCryptoError,
    InvalidUuid(String),
}

impl fmt::Display for OperationError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &OperationError::Action(ref expl_opt, ref cause) => {
                if let &Some(ref expl) = expl_opt {
                    write!(fmt, "Action did not succeed, {}: {}", expl, cause)
                } else {
                    write!(fmt, "Action did not succeed ({})", cause)
                }
            }
            &OperationError::InvalidOperation(ref expl) => {
                write!(fmt, "Invalid operation ({}). This is probably a bug.", expl)
            }
            &OperationError::ValidationFailed(ref expl) => write!(fmt, "Validation failed during operation: {}", expl),
            &OperationError::CryptOperationFailed(ref path, ref expl) => write!(
                fmt,
                "Cryptsetup operation failed for device '{}': {}",
                path.as_path().to_str().unwrap(),
                expl
            ),
            &OperationError::BackupDbOpenFailed => write!(fmt, "Opening backup database failed"),
            &OperationError::DbOpenFailed => write!(fmt, "Opening database failed"),
            &OperationError::DbSaveFailed => write!(fmt, "Saving database failed"),
            &OperationError::NotFoundInDb(ref expl) => write!(fmt, "Entry was not found in db: {}", expl),
            &OperationError::BugExplanation(ref expl) => write!(fmt, "BUG: {}", expl),
            &OperationError::FeatureNotAvailable => write!(fmt, "This feature is not available"),
            &OperationError::UnknownCryptoError => write!(fmt, "Unknown crypto operation error occurred"),
            &OperationError::InvalidUuid(ref expl) => write!(fmt, "{}", expl),
        }
    }
}

impl convert::From<context::Error> for OperationError {
    fn from(error: context::Error) -> OperationError {
        match error {
            context::Error::KeyfileInputError { cause } => {
                OperationError::Action(Some("Key file input failed".to_string()), cause)
            }
            context::Error::PasswordInputError { cause } => {
                OperationError::Action(Some("Passphrase input failed".to_string()), cause)
            }
            context::Error::DiskIoError { path, cause } => {
                OperationError::Action(Some(format!("Disk IO operation failed: {:?}", path)), cause)
            }
            context::Error::DatabaseIoError { path, cause } => OperationError::Action(
                Some(format!("IO operation failed for peroxide database {:?}", path)),
                cause,
            ),
            context::Error::YubikeyError { message } => {
                OperationError::Action(Some(message), io::Error::new(io::ErrorKind::Other, ""))
            }
            context::Error::FeatureNotAvailable => OperationError::FeatureNotAvailable,
            context::Error::UnknownCryptoError => OperationError::UnknownCryptoError,
        }
    }
}

impl<'a> convert::From<&'a context::Error> for OperationError {
    #[allow(unconditional_recursion)]
    fn from(error: &'a context::Error) -> OperationError {
        From::from(error.clone())
    }
}

impl<P: AsRef<Path>> convert::From<(P, cryptsetup_rs::Error)> for OperationError {
    fn from(pair: (P, cryptsetup_rs::Error)) -> OperationError {
        let (path, crypt_error) = pair;
        OperationError::CryptOperationFailed(path.as_ref().to_owned(), format!("{:?}", crypt_error))
    }
}

#[derive(Debug)]
enum PathOrUuid {
    Path(PathBuf),
    Uuid(uuid::Uuid),
}

impl FromStr for PathOrUuid {
    type Err = OperationError;

    fn from_str(path_or_uuid: &str) -> Result<PathOrUuid> {
        let maybe_uuid = uuid::Uuid::parse_str(path_or_uuid).ok();
        Ok(maybe_uuid
            .map(|uuid| PathOrUuid::Uuid(uuid))
            .unwrap_or(PathOrUuid::Path(PathBuf::from(path_or_uuid))))
    }
}

trait UserDiskLookup {
    fn resolve_paths_or_uuids<'a>(&self, paths_or_uuids: &'a [&'a str]) -> HashMap<&'a str, context::Result<PathBuf>>;
    fn uuid_of_path<P: AsRef<Path>>(&self, path: &P) -> Result<uuid::Uuid>;
}

trait PasswordPromptString {
    fn prompt_string(&self) -> String;
    fn prompt_name(&self) -> String;
}

impl PasswordPromptString for VolumeId {
    fn prompt_string(&self) -> String {
        format!("Please enter existing passphrase for {}: ", self.prompt_name())
    }

    fn prompt_name(&self) -> String {
        self.name
            .as_ref()
            .map(|name| format!("'{}'", name))
            .unwrap_or_else(|| format!("uuid={}", self.uuid()))
    }
}

impl<Context> UserDiskLookup for Context
where
    Context: context::DiskSelector,
{
    fn resolve_paths_or_uuids<'a>(&self, paths_or_uuids: &'a [&'a str]) -> HashMap<&'a str, context::Result<PathBuf>> {
        paths_or_uuids
            .iter()
            .map(|s| (s, PathOrUuid::from_str(s).unwrap()))
            .map(|(s, path_or_uuid)| {
                (
                    *s,
                    match path_or_uuid {
                        PathOrUuid::Path(path) => Ok(path),
                        PathOrUuid::Uuid(uuid) => self.disk_uuid_path(&uuid),
                    },
                )
            })
            .collect()
    }

    fn uuid_of_path<P: AsRef<Path>>(&self, path: &P) -> Result<uuid::Uuid> {
        cryptsetup_rs::luks1_uuid(path).map_err(|e| {
            OperationError::InvalidUuid(format!(
                "Unable to parse UUID from LUKS header of {}: {:?}",
                path.as_ref().to_string_lossy(),
                e
            ))
        })
    }
}

mod enroll;
mod list;
mod newdb;
mod open;
mod register;
