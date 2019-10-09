use std::fs::File;
use std::io;
use std::io::Read;
use std::path::PathBuf;

use crate::input::{KeyInput, Result, SecStr};

/// Parameters for key file input
pub struct KeyfilePrompt {
    /// Absolute path to the keyfile
    pub key_file: PathBuf,
}

impl KeyInput for KeyfilePrompt {
    fn get_key(&self, _prompt: &str) -> Result<SecStr> {
        let mut file = File::open(&self.key_file)?;
        let meta = file.metadata()?;
        let mut key = Vec::with_capacity(meta.len() as usize);
        let read = file.read_to_end(&mut key)?;
        if read == 0 {
            Err(From::from(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("Zero byte key file at {}", self.key_file.display()),
            )))
        } else {
            Ok(SecStr::new(key))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use expectest::prelude::*;

    use std::fs::File;
    use std::io::Write;
    use std::str;

    use tempfile::{Builder, TempDir};

    fn _write_keyfile(s: &str) -> Result<(TempDir, PathBuf)> {
        let tmp_dir = Builder::new().prefix("keyfile_prompt").tempdir()?;
        let keyfile = tmp_dir.path().join("keyfile");

        let mut tmp_file = File::create(&keyfile)?;
        write!(tmp_file, "{}", s)?;
        drop(tmp_file);

        Ok((tmp_dir, keyfile))
    }

    #[test]
    fn read_key_from_file() {
        let (_tmp_dir, key_file) = _write_keyfile("correcthorsebatterystaple").unwrap();

        let prompt = KeyfilePrompt { key_file };
        let key = prompt.get_key(&"").unwrap();
        let key_str = str::from_utf8(key.unsecure()).unwrap();

        expect!(key_str).to(be_equal_to("correcthorsebatterystaple"));
    }
}
