use std::cmp;
use std::io;
use std::io::{Read, Write};
use std::path;

use uuid::Uuid;

use serde_json;

pub const DB_VERSION: u16 = 1;

pub type Result<T> = io::Result<T>;

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum DbType {
	Operation,
	Backup,
}

#[derive(Serialize, Deserialize, Debug)]
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
	KeyfileEntry { key_file: path::PathBuf, volume_id: VolumeId },
	PassphraseEntry { volume_id: VolumeId },
	YubikeyEntry { entry_type: YubikeyEntryType, slot: YubikeySlot, volume_id: VolumeId },
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone)]
pub struct VolumeId {
	pub name: Option<String>,
	pub id: VolumeUuid
}

impl VolumeId {
	pub fn new(name: Option<String>, uuid: Uuid) -> VolumeId {
		VolumeId { name: name, id: VolumeUuid { uuid: uuid } }
	}
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct VolumeUuid {
	pub uuid: Uuid
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
            db_type: db_type,
            version: DB_VERSION,
        }
    }

    pub fn from<R>(reader: R) -> Result<PeroxideDb>
        where R: Read
    {
        serde_json::de::from_reader(reader).map_err(|err| io::Error::new(io::ErrorKind::Other, format!("{}", err)))
    }

    pub fn save<W>(&self, writer: &mut W) -> Result<()>
        where W: Write
    {
        let json = serde_json::to_string(self).unwrap();
        try!(writer.write_all(json.as_bytes()));
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

// TODO: Write tests for the serialization
