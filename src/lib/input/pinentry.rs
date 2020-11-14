use pinentry_rs::{pinentry, Error as PinentryError};
use std::time::Duration;

use crate::input::{Error, KeyInput, Result, SecStr};

/// A prompt using pinentry for password entry
pub struct PinentryPrompt {
    pub timeout: Option<Duration>,
}

impl KeyInput for PinentryPrompt {
    fn get_key(&self, prompt: &str) -> Result<SecStr> {
        // TODO better prompts
        let mut entry = pinentry().window_title("Unlock disk".to_string());

        if let Some(duration) = self.timeout {
            entry = entry.timeout(duration.as_secs() as u32)
        }

        let pin = entry.pin(prompt.to_string())?;

        Ok(pin)
    }
}

impl From<PinentryError> for Error {
    fn from(e: PinentryError) -> Self {
        Error::PinentryError(e)
    }
}
