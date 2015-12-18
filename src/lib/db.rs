include!(concat!(env!("OUT_DIR"), "/db.rs"));

use std::io;
use std::io::{Error, Read, Write};
use serde_json;

pub const DB_VERSION: u16 = 1;

pub type Result<T> = io::Result<T>;

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
