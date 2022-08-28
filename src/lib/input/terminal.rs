use std::time::Duration;

use snafu::prelude::*;

use ttypass;

use crate::input::{InputName, IoSnafu, KeyInput, Result, SecStr};

/// A terminal prompt for a key (password)
pub struct TerminalPrompt {
    pub timeout: Option<Duration>,
}

impl KeyInput for TerminalPrompt {
    fn get_key(&self, name: &InputName, is_new: bool) -> Result<SecStr> {
        let prompt = name.prompt_override.clone().unwrap_or_else(|| {
            if is_new {
                format!("Enter new passphrase for {}:", name.name)
            } else if let Some(ref uuid) = name.uuid {
                format!("Enter passphrase to unlock {} (uuid={}):", name.name, uuid)
            } else {
                format!("Enter passphrase to unlock {}:", name.name)
            }
        });

        let buf = ttypass::read_password(&prompt, self.timeout.clone()).context(IoSnafu)?;
        Ok(SecStr::new(buf))
    }
}
