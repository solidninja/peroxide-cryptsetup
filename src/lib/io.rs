use std::io;
use std::io::{Error, ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::fs;

use model::DbLocation;
use uuid;

pub type Result<T> = io::Result<T>;
pub use io::unsafe_passphrase::TerminalPrompt;

// the below assume udev or udev-like /dev layout
const DISK_BY_UUID: &'static str = "/dev/disk/by-uuid";
const DEV_MAPPER: &'static str = "/dev/mapper";


// TODO - look into libraries like common.rs for better secure buffer management
#[derive(PartialEq, Eq)]
pub struct KeyWrapper {
    data: Vec<u8>,
}

impl KeyWrapper {
    pub fn as_slice<'a>(&'a self) -> &'a [u8] {
        &self.data[..]
    }

    pub fn read<R: Read>(keyfile: &mut R) -> io::Result<KeyWrapper> {
        let mut buf = Vec::new();
        try!(keyfile.read_to_end(&mut buf));
        Ok(KeyWrapper { data: buf })
    }
}

impl Drop for KeyWrapper {
    fn drop(&mut self) {
        // FIXME - do nothing, relying on the drop() implementation of Vec to clear up any potential memory leakage
    }
}

pub trait FileExtensions {
    // TODO - maybe add AsRef<Path> ?
    fn relative_path(&self, other: &Path) -> Option<PathBuf>;
    fn open_relative_path(&self, other: &Path) -> io::Result<fs::File>;
    fn exists(&self) -> bool;
}

impl FileExtensions for DbLocation {
    fn relative_path(&self, other: &Path) -> Option<PathBuf> {
        // because path canonicalization is not available in stable, we have to attempt it here
        if other.is_relative() {
            let mut location = self.path.parent().unwrap().to_path_buf();
            location.push(other);
            if let Ok(meta) = fs::metadata(location) {
                if meta.is_file() {
                    return Some(other.to_path_buf());
                }
            }
        }

        None
    }

    fn open_relative_path(&self, other: &Path) -> io::Result<fs::File> {
        if let Some(relative_other) = self.relative_path(other) {
            let mut location = self.path.parent().unwrap().to_path_buf();
            location.push(relative_other);
            fs::File::open(location)
        } else {
            Err(Error::new(ErrorKind::NotFound, "File was not found"))
        }
    }

    fn exists(&self) -> bool {
        fs::metadata(&self.path).map(|meta| meta.is_file()).unwrap_or(false)
    }
}

pub struct Disks;

impl Disks {
    fn parse_uuid_from(path: &Path) -> Option<uuid::Uuid> {
        path.file_name()
            .and_then(|file_name| file_name.to_str())
            .and_then(|file_name| uuid::Uuid::parse_str(file_name).ok())
    }

    pub fn all_disk_uuids() -> io::Result<Vec<uuid::Uuid>> {
        // assume udev
        fs::read_dir(Path::new(DISK_BY_UUID)).and_then(|entries| {
            entries.map(|entry| {
                       entry.map(|e| e.path())
                            .and_then(|p| Disks::parse_uuid_from(&p).ok_or(Error::new(ErrorKind::Other, "Uuid parsing failed")))
                   })
                   .collect()
        })
    }

    pub fn disk_uuid_path(uuid: &uuid::Uuid) -> io::Result<PathBuf> {
        let path = Path::new(DISK_BY_UUID).join(uuid.to_hyphenated_string());

        fs::metadata(&path).and_then(|meta| {
            if meta.is_file() {
                Ok(path)
            } else {
                Err(io::Error::new(io::ErrorKind::NotFound,
                                   format!("Disk path {} is not a file", path.display())))
            }
        })
    }

    pub fn is_device_mapped(name: &str) -> bool {
        let path = Path::new(DEV_MAPPER).join(name);
        fs::metadata(&path)
            .map(|meta| !meta.is_dir())
            .unwrap_or(false)
    }
}

mod unsafe_passphrase {
    use std::io;
    use std::io::{Read, Write};
    use std::time::Duration;
    use std::os::unix::io::{AsRawFd, RawFd};
    use std::mem;
    use std::ptr;
    use std::fs;

    use libc;

    use super::KeyWrapper;

    const DEV_TTY: &'static str = "/dev/tty";
    const MAX_PASSPHRASE_LENGTH: usize = 255;

    pub struct TerminalPrompt;

    // TODO - write a test for ensuring LF does not appear at the end of output

    impl TerminalPrompt {
        fn read_passphrase<R: Read>(reader: &mut R) -> io::Result<KeyWrapper> {
            let mut buf = [0u8; MAX_PASSPHRASE_LENGTH];
            let len = try!(reader.read(&mut buf));
            if len == 0 {
                Err(io::Error::new(io::ErrorKind::Other,
                                   "Unexpected EOF while reading".to_string()))
            } else {
                let key_wrapper = KeyWrapper { data: buf[..len - 1].to_vec() };
                // TODO - erase the contents of buf
                Ok(key_wrapper)
            }
        }

        fn read_passphrase_timeout<R: Read>(reader: &mut R, read_fd: RawFd, maybe_timeout: Option<&Duration>) -> io::Result<KeyWrapper> {
            if let Some(timeout) = maybe_timeout {
                // FIXME - better way to do this, surely.
                unsafe {
                    let fd_set = libc::malloc(mem::size_of::<libc::fd_set>() as libc::size_t) as *mut libc::fd_set;
                    assert!(!fd_set.is_null());
                    libc::FD_ZERO(fd_set);
                    libc::FD_SET(read_fd, fd_set);

                    let mut timeval = libc::timeval {
                        tv_sec: timeout.as_secs() as libc::time_t,
                        tv_usec: timeout.subsec_nanos() as libc::suseconds_t,
                    };
                    let key = if libc::select(read_fd + 1,
                                              fd_set,
                                              ptr::null_mut(),
                                              ptr::null_mut(),
                                              &mut timeval as *mut libc::timeval) > 0 {
                        TerminalPrompt::read_passphrase(reader)
                    } else {
                        Err(io::Error::new(io::ErrorKind::TimedOut,
                                           "Timed out while reading".to_string()))
                    };

                    assert!(!fd_set.is_null());
                    libc::free(fd_set as *mut libc::c_void);

                    key
                }
            } else {
                TerminalPrompt::read_passphrase(reader)
            }
        }

        pub fn prompt_passphrase(prompt: &str, timeout: Option<&Duration>) -> io::Result<KeyWrapper> {
            use termios::*;

            let mut tty_file = try!(fs::OpenOptions::new().read(true).write(true).open(DEV_TTY));
            let fd = tty_file.as_raw_fd();
            let mut orig_termios = try!(Termios::from_fd(fd));
            let mut prompt_termios = orig_termios.clone();

            // write out prompt
            try!(tty_file.write(prompt.as_bytes()));

            // set flags for prompt termios
            prompt_termios.c_lflag &= !ECHO;

            try!(tcsetattr(fd, TCSAFLUSH, &mut prompt_termios));
            let key = try!(TerminalPrompt::read_passphrase_timeout(&mut tty_file, fd, timeout));

            // reset flags
            try!(tcsetattr(fd, TCSAFLUSH, &mut orig_termios));

            // write out newline
            try!(tty_file.write(b"\n"));

            Ok(key)
        }
    }
}

#[cfg(feature = "yubikey")]
pub mod yubikey {
    use super::KeyWrapper;

    pub fn wrap(key: &[u8]) -> KeyWrapper {
        KeyWrapper { data: key.to_vec() }
    }
}


#[cfg(test)]
pub mod tests {
    use super::*;
    use tempfile::TempFile;
    use tempdir::TempDir;
    use std::io;
    use std::io::{Seek, Read, Write};
    use model::{DbType, DbLocation, PeroxideDb};

    use expectest::prelude::*;

    pub struct DbLocationWrapper(pub TempDir, pub DbLocation);

    impl PeroxideDb {
        pub fn new_temporary_db(db_type: DbType) -> (PeroxideDb, DbLocationWrapper) {
            let db = PeroxideDb::new(db_type.clone());
            let temp_dir = TempDir::new("db_test").unwrap();
            let db_location = DbLocation {
                path: temp_dir.path().join("temp.db"),
                db_type: db_type,
            };

            (db, DbLocationWrapper(temp_dir, db_location))
        }
    }


    impl KeyWrapper {
        pub fn save_in<W: Read + Write + Seek>(file: &mut W, contents: &[u8]) -> io::Result<KeyWrapper> {
            try!(file.seek(io::SeekFrom::Start(0)));
            try!(file.write_all(contents));
            try!(file.seek(io::SeekFrom::Start(0)));
            KeyWrapper::read(file)
        }
    }

    // TODO - write tests for the relativisation of paths
    // TODO - how to test that secret key is gone from memory instead of relying on rust zeroing it out for us

    #[test]
    fn test_load_key_from_file() {
        let mut temp_keyfile = TempFile::new().unwrap();
        let contents = vec![0xD, 0xE, 0xA, 0xD, 0xB, 0xE, 0xE, 0xF];
        let key_wrapper = KeyWrapper::save_in(&mut temp_keyfile, &contents).unwrap();

        assert_eq!(contents, key_wrapper.data);
    }

    #[test]
    fn test_all_disks_uuids_must_return_something() {
        let maybe_uuids = Disks::all_disk_uuids();
        expect!(maybe_uuids).to(be_ok());
    }

    // TODO - write test for disk path

}
