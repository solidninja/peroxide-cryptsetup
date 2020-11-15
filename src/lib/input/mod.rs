use std::error;
use std::fmt::Display;
use std::io;
use std::path::Path;
use std::result;
use std::time::Duration;

pub use secstr::SecStr;
use uuid::Uuid;

#[cfg(feature = "yubikey")]
use ykpers_rs::Error as YubikeyError;

#[cfg(feature = "pinentry")]
use pinentry_rs::Error as PinEntryError;

use crate::db::{DbEntry, YubikeyEntryType, YubikeySlot};
use serde::export::Formatter;

#[derive(Debug)]
pub enum Error {
    FeatureNotAvailable,
    IoError(io::Error),
    UnknownCryptoError,
    #[cfg(feature = "yubikey")]
    YubikeyError(YubikeyError),
    #[cfg(feature = "pinentry")]
    PinentryError(PinEntryError),
}

pub type Result<T> = result::Result<T, Error>;

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::IoError(e)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::FeatureNotAvailable => write!(f, "Feature is not available"),
            Error::IoError(ref cause) => write!(f, "I/O error: {}", cause),
            Error::UnknownCryptoError => write!(f, "Unknown crypto error - yikes!"),
            #[cfg(feature = "yubikey")]
            Error::YubikeyError(ref cause) => write!(f, "Yubikey error: {:?}", cause), // TODO: formatting
            #[cfg(feature = "pinentry")]
            Error::PinentryError(ref cause) => write!(f, "Pinentry error: {:?}", cause), // TODO: formatting
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::IoError(ref cause) => Some(cause),
            Error::YubikeyError(ref cause) => Some(cause),
            Error::PinentryError(ref cause) => Some(cause),
            _ => None,
        }
    }
}

// FIXME: change the prompt get_key to take in a DbEntry

pub struct InputName {
    pub name: String,
    pub uuid: Option<uuid::Uuid>,
    pub prompt_override: Option<String>,
}

impl InputName {
    pub fn blank() -> InputName {
        InputName {
            name: "".to_string(),
            uuid: None,
            prompt_override: None,
        }
    }

    pub fn with_override(name: String, prompt_override: String) -> InputName {
        InputName {
            name,
            uuid: None,
            prompt_override: Some(prompt_override),
        }
    }
}

/// Interface for getting key data (whether from a terminal, a file, etc.)
pub trait KeyInput {
    fn get_key(&self, name: &InputName) -> Result<SecStr>;
}

#[derive(Debug)]
pub struct KeyInputConfig {
    /// Timeout for password input (on terminal or elsewhere)
    pub password_input_timeout: Option<Duration>,
}

/// Get a key for a given db entry
pub fn get_key_for<P: AsRef<Path>>(
    db_entry: &DbEntry,
    key_input_config: &KeyInputConfig,
    working_dir: P,
    name_override: Option<String>,
    prompt_override: Option<String>,
) -> Result<SecStr> {
    let method = get_input_method_for(db_entry, key_input_config, working_dir)?;
    let name = name_override
        .or(db_entry.volume_id().name.clone())
        .unwrap_or_else(|| "unknown".to_string());
    let uuid = db_entry.uuid().to_owned();
    let input = InputName {
        name,
        uuid: Some(uuid),
        prompt_override,
    };
    method.get_key(&input)
}

/// Dispatch on db entry type to get the appropriate key input method
fn get_input_method_for<P: AsRef<Path>>(
    db_entry: &DbEntry,
    key_input_config: &KeyInputConfig,
    working_dir: P,
) -> Result<Box<dyn KeyInput>> {
    match db_entry {
        &DbEntry::KeyfileEntry { ref key_file, .. } => Ok(Box::new(keyfile(&key_file, working_dir.as_ref())?)),
        &DbEntry::PassphraseEntry { .. } => Ok(Box::new(passphrase(key_input_config.password_input_timeout))),
        &DbEntry::YubikeyEntry {
            entry_type,
            slot,
            ref volume_id,
        } => {
            let passphrase_input = Box::new(passphrase(key_input_config.password_input_timeout));
            Ok(Box::new(yubikey(
                entry_type,
                passphrase_input,
                slot,
                volume_id.uuid().clone(),
            )))
        }
    }
}

/// Create parameters for a passphrase input (a terminal)
#[cfg(not(feature = "pinentry"))]
fn passphrase(timeout: Option<Duration>) -> impl KeyInput {
    terminal::TerminalPrompt { timeout }
}

/// Create parameters for a passphrase input (using pinentry)
#[cfg(feature = "pinentry")]
fn passphrase(timeout: Option<Duration>) -> impl KeyInput {
    pinentry::PinentryPrompt { timeout }
}

/// Create parameters for a keyfile input (a physical file)
fn keyfile(key_path: &Path, working_dir: &Path) -> Result<impl KeyInput> {
    // The key path may be relative to a working directory (which is typically the directory the peroxide db is in)
    let key_file = if key_path.is_relative() {
        working_dir.to_path_buf().join(key_path).canonicalize()?
    } else {
        key_path.to_path_buf().canonicalize()?
    };
    debug!("Will read from key path {}", key_file.display());

    Ok(keyfile::KeyfilePrompt { key_file })
}

#[cfg(not(feature = "yubikey"))]
fn yubikey(
    entry_type: YubikeyEntryType,
    passphrase_input: Box<dyn KeyInput>,
    slot: YubikeySlot,
    uuid: Uuid,
) -> impl KeyInput {
    Err(Error::FeatureNotAvailable)
}

/// Create parameters for a Yubikey challenge-response (or hybrid) input
#[cfg(feature = "yubikey")]
fn yubikey(
    entry_type: YubikeyEntryType,
    passphrase_input: Box<dyn KeyInput>,
    slot: YubikeySlot,
    uuid: Uuid,
) -> impl KeyInput {
    yubikey::YubikeyPrompt {
        entry_type,
        passphrase_input,
        slot,
        uuid,
    }
}

mod keyfile;
mod terminal;

#[cfg(feature = "yubikey")]
mod yubikey;

#[cfg(feature = "pinentry")]
mod pinentry;
