use std::time::Duration;

use pinentry_rs::pinentry;
use snafu::prelude::*;

use crate::input::{InputName, KeyInput, PinentrySnafu, Result, SecStr};

/// A prompt using pinentry for password entry
pub struct PinentryPrompt {
    pub timeout: Option<Duration>,
}

impl KeyInput for PinentryPrompt {
    fn get_key(&self, name: &InputName, is_new: bool) -> Result<SecStr> {
        let prompt = name.prompt_override.clone().unwrap_or_else(|| {
            if is_new {
                format!("Enter new passphrase for {}:", name.name)
            } else if let Some(ref uuid) = name.uuid {
                format!("Enter passphrase for disk {} (uuid={}):", name.name, uuid)
            } else {
                format!("Enter passphrase for disk {}:", name.name)
            }
        });
        let title = if is_new {
            format!("New passphrase")
        } else if let Some(ref uuid) = name.uuid {
            format!("Unlock disk (uuid={})", uuid)
        } else {
            format!("Unlock disk")
        };

        let mut entry = pinentry().window_title(title);

        if let Some(duration) = self.timeout {
            entry = entry.timeout(duration.as_secs() as u32)
        }

        let pin = entry.pin(prompt).context(PinentrySnafu {})?;

        Ok(pin)
    }
}
