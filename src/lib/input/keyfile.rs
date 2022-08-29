use std::fs::File;
use std::io;
use std::io::Read;
use std::path::PathBuf;

use snafu::prelude::*;

use crate::input::{FileNotFoundSnafu, InputName, IoSnafu, KeyInput, Result, SecStr};

/// Parameters for key file input
pub struct KeyfilePrompt {
    /// Absolute path to the keyfile
    pub key_file: PathBuf,
}

impl KeyInput for KeyfilePrompt {
    fn get_key(&self, _name: &InputName, _is_new: bool) -> Result<SecStr> {
        if !self.key_file.exists() {
            return Err(FileNotFoundSnafu {
                path: self.key_file.clone(),
            }
            .build());
        }

        let mut file = File::open(&self.key_file).context(IoSnafu)?;
        let meta = file.metadata().context(IoSnafu)?;
        let mut key = Vec::with_capacity(meta.len() as usize);
        let read = file.read_to_end(&mut key).context(IoSnafu)?;
        if read == 0 {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("Zero byte key file at {}", self.key_file.display()),
            ))
            .context(IoSnafu)
        } else {
            Ok(SecStr::new(key))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write;
    use std::str;

    use expectest::prelude::*;
    use snafu::prelude::*;
    use tempfile::{Builder, TempDir};

    use crate::input::IoSnafu;

    use super::*;

    fn _write_keyfile(s: &str) -> Result<(TempDir, PathBuf)> {
        let tmp_dir = Builder::new().prefix("keyfile_prompt").tempdir().context(IoSnafu)?;
        let keyfile = tmp_dir.path().join("keyfile");

        let mut tmp_file = File::create(&keyfile).context(IoSnafu)?;
        write!(tmp_file, "{}", s).context(IoSnafu)?;
        drop(tmp_file);

        Ok((tmp_dir, keyfile))
    }

    #[test]
    fn read_key_from_file() -> Result<()> {
        let (_tmp_dir, key_file) = _write_keyfile("correcthorsebatterystaple")?;

        let prompt = KeyfilePrompt { key_file };
        let key = prompt.get_key(&InputName::blank(), false)?;
        let key_str = str::from_utf8(key.unsecure()).expect("unsecure key to utf8");

        expect!(key_str).to(be_equal_to("correcthorsebatterystaple"));

        Ok(())
    }
}
