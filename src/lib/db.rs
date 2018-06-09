use std::cmp;
use std::io;
use std::io::{Read, Write};
use std::path;

use uuid::Uuid;

use serde_json;

pub const DB_VERSION: u16 = 1;

pub type Result<T> = io::Result<T>;

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbType {
    Operation,
    Backup,
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
pub type YubikeySlot = u8;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Copy)]
pub enum YubikeyEntryType {
    ChallengeResponse,
    HybridChallengeResponse,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum DbEntry {
    KeyfileEntry {
        key_file: path::PathBuf,
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

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone)]
pub struct VolumeId {
    pub name: Option<String>,
    pub id: VolumeUuid,
}

impl VolumeId {
    pub fn new(name: Option<String>, uuid: Uuid) -> VolumeId {
        VolumeId {
            name,
            id: VolumeUuid { uuid },
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct VolumeUuid {
    pub uuid: Uuid,
}

impl cmp::Ord for VolumeUuid {
    fn cmp(&self, other: &VolumeUuid) -> cmp::Ordering {
        self.uuid.cmp(&other.uuid)
    }
}

impl cmp::PartialOrd for VolumeUuid {
    fn partial_cmp(&self, other: &VolumeUuid) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PeroxideDb {
    pub fn new(db_type: DbType) -> PeroxideDb {
        PeroxideDb {
            entries: vec![],
            db_type,
            version: DB_VERSION,
        }
    }

    pub fn from<R>(reader: R) -> Result<PeroxideDb>
    where
        R: Read,
    {
        serde_json::de::from_reader(reader).map_err(|err| io::Error::new(io::ErrorKind::Other, format!("{}", err)))
    }

    pub fn save<W>(&self, writer: &mut W) -> Result<()>
    where
        W: Write,
    {
        let json = serde_json::to_string(self).unwrap();
        writer.write_all(json.as_bytes())?;
        Ok(())
    }
}

impl DbEntry {
    pub fn volume_id<'a>(&'a self) -> &'a VolumeId {
        match *self {
            DbEntry::KeyfileEntry { ref volume_id, .. } => volume_id,
            DbEntry::PassphraseEntry { ref volume_id, .. } => volume_id,
            DbEntry::YubikeyEntry { ref volume_id, .. } => volume_id,
        }
    }

    pub fn uuid<'a>(&'a self) -> &'a Uuid {
        &self.volume_id().id.uuid
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
        expect!(serde_json::to_string(&VolumeId::new(None, Uuid::nil())))
            .to(be_ok().value(r#"{"name":null,"id":{"uuid":"00000000-0000-0000-0000-000000000000"}}"#.to_string()));
        expect!(serde_json::to_string(&VolumeId::new(
            Some("foobar".to_string()),
            Uuid::nil()
        ))).to(be_ok().value(r#"{"name":"foobar","id":{"uuid":"00000000-0000-0000-0000-000000000000"}}"#.to_string()));
    }

    #[test]
    fn test_serialize_keyfile_entry() {
        let entry = DbEntry::KeyfileEntry {
            key_file: PathBuf::from("/path/to/keyfile"),
            volume_id: VolumeId::new(None, Uuid::nil()),
        };
        expect!(serde_json::to_string(&entry)).to(be_ok().value(r#"{"KeyfileEntry":{"key_file":"/path/to/keyfile","volume_id":{"name":null,"id":{"uuid":"00000000-0000-0000-0000-000000000000"}}}}"#.to_string()));
    }

    #[test]
    fn test_serialize_passphrase_entry() {
        let entry = DbEntry::PassphraseEntry {
            volume_id: VolumeId::new(None, Uuid::nil()),
        };
        expect!(serde_json::to_string(&entry)).to(be_ok().value(
            r#"{"PassphraseEntry":{"volume_id":{"name":null,"id":{"uuid":"00000000-0000-0000-0000-000000000000"}}}}"#.to_string(),
        ));
    }

    #[test]
    fn test_serialize_yubikey_entry() {
        let entry = DbEntry::YubikeyEntry {
            entry_type: YubikeyEntryType::HybridChallengeResponse,
            slot: 1,
            volume_id: VolumeId::new(None, Uuid::nil()),
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
            volume_id: VolumeId::new(Some("test-disk".to_string()), Uuid::nil()),
        });
        expect!(serde_json::from_str::<PeroxideDb>(db_json)).to(be_ok().value(db.clone()));
    }

}
