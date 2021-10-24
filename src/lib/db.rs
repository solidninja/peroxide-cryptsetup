use std::env::current_dir;
use std::fmt;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::result;

use uuid::Uuid;

use serde_json;
use std::str::FromStr;

/// Current database version (used for future forward-compatibility)
pub const DB_VERSION: u16 = 1;

/// Default database name
pub const PEROXIDE_DB_NAME: &'static str = "peroxs-db.json";

#[derive(Debug)]
pub enum Error {
    DatabaseNotFound(PathBuf),
    IoError(PathBuf, io::Error),
    SerialisationError(serde_json::Error),
}

pub type Result<T> = result::Result<T, Error>;

impl<P: AsRef<Path>> From<(P, io::Error)> for Error {
    fn from(e: (P, io::Error)) -> Self {
        if e.1.kind() == std::io::ErrorKind::NotFound {
            Error::DatabaseNotFound(e.0.as_ref().to_path_buf())
        } else {
            Error::IoError(e.0.as_ref().to_path_buf(), e.1)
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::SerialisationError(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::DatabaseNotFound(ref path) => write!(f, "Database not found at {}", path.display()),
            Error::IoError(ref path, ref e) => write!(f, "I/O error [database={}, cause={}]", path.display(), e),
            Error::SerialisationError(ref e) => write!(f, "Database serialisation error [cause={}]", e),
        }
    }
}

// TODO - either justify the backup db type or get rid of it
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbType {
    Operation,
    Backup,
}

impl FromStr for DbType {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_ref() {
            "operation" => Ok(DbType::Operation),
            "backup" => Ok(DbType::Backup),
            other => Err(format!("Invalid DbType '{}'", other)),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PeroxideDb {
    pub entries: Vec<DbEntry>,
    pub db_type: DbType,
    pub version: u16,
}

#[derive(Debug, Clone, Copy)]
pub enum DbEntryType {
    Keyfile,
    Passphrase,
    Yubikey,
}

// FIXME move this to newtype
// FIXME #[serde(flatten)]
pub type YubikeySlot = u8;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Copy)]
pub enum YubikeyEntryType {
    ChallengeResponse,
    HybridChallengeResponse,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum DbEntry {
    KeyfileEntry {
        key_file: PathBuf,
        volume_id: VolumeId,
    },
    PassphraseEntry {
        volume_id: VolumeId,
    },
    YubikeyEntry {
        entry_type: YubikeyEntryType,
        slot: YubikeySlot,
        volume_id: VolumeId,
    },
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone, Ord, PartialOrd)]
pub struct VolumeId {
    pub name: Option<String>,
    // Note this is necessary to preserve JSON compatibility with the pre-serde version of peroxide-cryptsetup
    // that had its own serialiser for UUID types (and this workaround is easier than writing a custom Serde serialiser)
    id: VolumeUuid,
    // LUKS 2 token id
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub(crate) luks2_token_id: Option<i32>,
}

impl VolumeId {
    pub fn new(name: Option<String>) -> VolumeId {
        VolumeId {
            name,
            id: VolumeUuid { uuid: Uuid::new_v4() },
            luks2_token_id: None,
        }
    }

    pub fn of(name: Option<String>, uuid: Uuid) -> VolumeId {
        VolumeId {
            name,
            id: VolumeUuid { uuid },
            luks2_token_id: None,
        }
    }

    pub fn uuid(&self) -> &Uuid {
        &self.id.uuid
    }
}

impl fmt::Display for VolumeId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(ref name) = self.name {
            write!(f, "Volume({}, {})", name, self.uuid())
        } else {
            write!(f, "Volume({})", self.uuid())
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Ord, PartialOrd)]
struct VolumeUuid {
    pub uuid: Uuid,
}

impl PeroxideDb {
    pub fn new(db_type: DbType) -> PeroxideDb {
        PeroxideDb {
            entries: vec![],
            db_type,
            version: DB_VERSION,
        }
    }

    /// Get the default location of the database (at the current directory called `peroxide-db.json`)
    pub fn default_location() -> Result<PathBuf> {
        current_dir()
            .map(|p| p.join(PEROXIDE_DB_NAME))
            .map_err(|e| (PathBuf::from("/invalid/current/dir"), e))
            .map_err(From::from)
    }

    /// Open a JSON-encoded database
    pub fn open<R: Read>(reader: R) -> Result<PeroxideDb> {
        serde_json::de::from_reader(reader).map_err(From::from)
    }

    /// Open a JSON-encoded database at the specified path
    pub fn open_at<P: AsRef<Path>>(path: P) -> Result<PeroxideDb> {
        PeroxideDb::open(File::open(path.as_ref()).map_err(|e| (path, e))?)
    }

    /// Write a JSON-encoded database
    pub fn save<W: Write>(&self, writer: &mut W) -> Result<()> {
        serde_json::to_writer(writer, self).map_err(From::from)
    }

    /// Write a JSON-encoded database to the specified path
    pub fn save_to<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        self.save(&mut File::create(path.as_ref()).map_err(|e| (path, e))?)
    }
}

impl DbEntry {
    pub fn volume_id(&self) -> &VolumeId {
        match *self {
            DbEntry::KeyfileEntry { ref volume_id, .. } => volume_id,
            DbEntry::PassphraseEntry { ref volume_id, .. } => volume_id,
            DbEntry::YubikeyEntry { ref volume_id, .. } => volume_id,
        }
    }

    pub fn uuid(&self) -> &Uuid {
        &self.volume_id().uuid()
    }

    pub fn volume_id_mut(&mut self) -> &mut VolumeId {
        match *self {
            DbEntry::KeyfileEntry { ref mut volume_id, .. } => volume_id,
            DbEntry::PassphraseEntry { ref mut volume_id, .. } => volume_id,
            DbEntry::YubikeyEntry { ref mut volume_id, .. } => volume_id,
        }
    }
}

#[cfg(test)]
pub mod tests {

    use super::*;

    use expectest::prelude::*;

    use serde_json;
    use std::path::PathBuf;
    use uuid::Uuid;

    #[test]
    fn test_serialize_db_type() {
        expect!(serde_json::to_string(&DbType::Operation)).to(be_ok().value(r#""Operation""#.to_string()));
        expect!(serde_json::to_string(&DbType::Backup)).to(be_ok().value(r#""Backup""#.to_string()));
    }

    #[test]
    fn test_serialize_yubikey_entry_type() {
        expect!(serde_json::to_string(&YubikeyEntryType::ChallengeResponse))
            .to(be_ok().value(r#""ChallengeResponse""#.to_string()));
        expect!(serde_json::to_string(&YubikeyEntryType::HybridChallengeResponse))
            .to(be_ok().value(r#""HybridChallengeResponse""#.to_string()));
    }

    #[test]
    fn test_serialize_volume_id() {
        expect!(serde_json::to_string(&VolumeId::of(None, Uuid::nil())))
            .to(be_ok().value(r#"{"name":null,"id":{"uuid":"00000000-0000-0000-0000-000000000000"}}"#.to_string()));
        expect!(serde_json::to_string(&VolumeId::of(
            Some("foobar".to_string()),
            Uuid::nil()
        )))
        .to(be_ok().value(r#"{"name":"foobar","id":{"uuid":"00000000-0000-0000-0000-000000000000"}}"#.to_string()));
    }

    #[test]
    fn test_serialize_keyfile_entry() {
        let entry = DbEntry::KeyfileEntry {
            key_file: PathBuf::from("/path/to/keyfile"),
            volume_id: VolumeId::of(None, Uuid::nil()),
        };
        expect!(serde_json::to_string(&entry)).to(be_ok().value(r#"{"KeyfileEntry":{"key_file":"/path/to/keyfile","volume_id":{"name":null,"id":{"uuid":"00000000-0000-0000-0000-000000000000"}}}}"#.to_string()));
    }

    #[test]
    fn test_serialize_passphrase_entry() {
        let entry = DbEntry::PassphraseEntry {
            volume_id: VolumeId::of(None, Uuid::nil()),
        };
        expect!(serde_json::to_string(&entry)).to(be_ok().value(
            r#"{"PassphraseEntry":{"volume_id":{"name":null,"id":{"uuid":"00000000-0000-0000-0000-000000000000"}}}}"#
                .to_string(),
        ));
    }

    #[test]
    fn test_serialize_passphrase_entry_luks2_token_id() {
        let volume_id = {
            let mut id = VolumeId::of(None, Uuid::nil());
            id.luks2_token_id = Some(42);
            id
        };

        let entry = DbEntry::PassphraseEntry { volume_id };
        expect!(serde_json::to_string(&entry)).to(be_ok().value(
            r#"{"PassphraseEntry":{"volume_id":{"name":null,"id":{"uuid":"00000000-0000-0000-0000-000000000000"},"luks2_token_id":42}}}"#
                .to_string(),
        ));
    }

    #[test]
    fn test_serialize_yubikey_entry() {
        let entry = DbEntry::YubikeyEntry {
            entry_type: YubikeyEntryType::HybridChallengeResponse,
            slot: 1,
            volume_id: VolumeId::of(None, Uuid::nil()),
        };
        expect!(serde_json::to_string(&entry)).to(be_ok().value(r#"{"YubikeyEntry":{"entry_type":"HybridChallengeResponse","slot":1,"volume_id":{"name":null,"id":{"uuid":"00000000-0000-0000-0000-000000000000"}}}}"#.to_string()));
    }

    #[test]
    fn test_serialize_database() {
        let db = PeroxideDb::new(DbType::Operation);
        expect!(serde_json::to_string(&db)).to(be_ok().value(r#"{"entries":[],"db_type":"Operation","version":1}"#));
    }

    #[test]
    fn test_deserialize_small_database() {
        let db_json = r#"{"entries":[{"KeyfileEntry":{"key_file":"keyfile.key","volume_id":{"name":"test-disk","id":{"uuid":"00000000-0000-0000-0000-000000000000"}}}}],"db_type":"Backup","version":1}"#;
        let mut db = PeroxideDb::new(DbType::Backup);
        db.entries.push(DbEntry::KeyfileEntry {
            key_file: PathBuf::from("keyfile.key"),
            volume_id: VolumeId::of(Some("test-disk".to_string()), Uuid::nil()),
        });
        expect!(serde_json::from_str::<PeroxideDb>(db_json)).to(be_ok().value(db.clone()));
    }
}
