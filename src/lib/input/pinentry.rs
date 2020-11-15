use pinentry_rs::{pinentry, Error as PinentryError};
use std::time::Duration;

use crate::input::{Error, InputName, KeyInput, Result, SecStr};

/// A prompt using pinentry for password entry
pub struct PinentryPrompt {
    pub timeout: Option<Duration>,
}

impl KeyInput for PinentryPrompt {
    fn get_key(&self, name: &InputName) -> Result<SecStr> {
        let prompt = name.prompt_override.clone().unwrap_or_else(|| {
            if let Some(ref uuid) = name.uuid {
                format!("Enter passphrase for disk {} (uuid={})", name.name, uuid)
            } else {
                format!("Enter passphrase for disk {}", name.name)
            }
        });
        let title = if let Some(ref uuid) = name.uuid {
            format!("Unlock disk (uuid={})", uuid)
        } else {
            format!("Unlock disk")
        };

        let mut entry = pinentry().window_title(title);

        if let Some(duration) = self.timeout {
            entry = entry.timeout(duration.as_secs() as u32)
        }

        let pin = entry.pin(prompt)?;

        Ok(pin)
    }
}

impl From<PinentryError> for Error {
    fn from(e: PinentryError) -> Self {
        Error::PinentryError(e)
    }
}
