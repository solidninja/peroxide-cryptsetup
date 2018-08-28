use std::time::Duration;

use input::{KeyInput, Result, SecStr};
use ttypass;

/// A terminal prompt for a key (password)
pub struct TerminalPrompt {
    pub timeout: Option<Duration>,
}

impl KeyInput for TerminalPrompt {
    fn get_key(&self, prompt: &str) -> Result<SecStr> {
        let buf = ttypass::read_password(prompt, self.timeout.clone())?;
        Ok(SecStr::new(buf))
    }
}
