use std::time::Duration;

use crate::input::{InputName, KeyInput, Result, SecStr};
use ttypass;

/// A terminal prompt for a key (password)
pub struct TerminalPrompt {
    pub timeout: Option<Duration>,
}

impl KeyInput for TerminalPrompt {
    fn get_key(&self, name: &InputName) -> Result<SecStr> {
        let prompt = name.prompt_override.clone().unwrap_or_else(|| {
            if let Some(ref uuid) = name.uuid {
                format!("Enter password to unlock {} (uuid={}):", name.name, uuid)
            } else {
                format!("Enter password to unlock {}:", name.name)
            }
        });

        let buf = ttypass::read_password(&prompt, self.timeout.clone())?;
        Ok(SecStr::new(buf))
    }
}
