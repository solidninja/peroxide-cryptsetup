use db;
use context;
use operation::{PerformCryptOperation, RegisterOperation, Result, OperationError, UserDiskLookup};

use std::path::Path;

impl<Context: context::WriterContext> PerformCryptOperation for RegisterOperation<Context> {
    fn apply(&self) -> Result<()> {
        let mut db = self.context.open_peroxide_db().map_err(|_| OperationError::DbOpenFailed)?;
        self.add_entry_from_args(&mut db)?;
        self.context.save_peroxide_db(&db)?;
        Ok(())
    }
}

impl<Context: context::WriterContext> RegisterOperation<Context>
{
    fn add_entry_from_args(&self, db: &mut db::PeroxideDb) -> Result<()> {
        // need to do this to get Vec<String> -> &[&str] TODO probably a better way
        let device_paths_or_uuids: Vec<&str> = self.device_paths_or_uuids.iter().map(|s| s.as_ref()).collect();
        let disk_paths = self.context.resolve_paths_or_uuids(&device_paths_or_uuids);
        let entries = disk_paths.values()
            .map(|res| res.as_ref().map_err(From::from).and_then(|path| self.to_entry(path)))
            .collect::<Result<Vec<_>>>()?;
        for entry in entries {
            db.entries.push(entry);
        }
        Ok(())
    }

    fn to_entry<P>(&self, path: &P) -> Result<db::DbEntry> where P: AsRef<Path> {
        let uuid = self.context.uuid_of_path(path)?;
        let volume_id: db::VolumeId = db::VolumeId::new(self.name.clone(), uuid.clone());
        match self.entry_type {
            db::DbEntryType::Keyfile => Ok(db::DbEntry::KeyfileEntry {
                volume_id,
                key_file: self.keyfile.clone().expect("Expected keyfile to be passed in")
            }),
            db::DbEntryType::Passphrase => Ok(db::DbEntry::PassphraseEntry {
                volume_id
            }),
            other => Err(OperationError::BugExplanation(format!("Entry type {:?} not supported in register operation", other)))
        }
    }
}