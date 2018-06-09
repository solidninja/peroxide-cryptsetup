use context;
use db::{DbEntry, YubikeyEntryType};
use operation::{ListOperation, OperationError, PerformCryptOperation, Result};

use prettytable::{format, Table};

impl<Context: context::ReaderContext + context::DiskSelector> PerformCryptOperation for ListOperation<Context> {
    fn apply(&self) -> Result<()> {
        let db = self.context
            .open_peroxide_db()
            .map_err(|_| OperationError::DbOpenFailed)?;

        // sort entries by name, then by uuid
        let mut entries = db.entries.clone();
        entries.sort_by_key(|entry| {
            let id = DbEntry::volume_id(entry).clone();
            (id.name, id.id)
        });

        let mut table = Table::new();
        table.add_row(row![b->"Name", b->"Type", b->"Uuid", b->"Disk"]);

        for entry in entries.iter() {
            self.add_table_entry(&mut table, entry);
        }

        table.set_format(*format::consts::FORMAT_CLEAN);
        table.printstd();

        Ok(())
    }
}

impl<Context> ListOperation<Context>
where
    Context: context::ReaderContext + context::DiskSelector,
{
    fn add_table_entry(&self, table: &mut Table, entry: &DbEntry) -> () {
        let id = DbEntry::volume_id(entry);
        let name = id.name.clone().unwrap_or("".to_string());
        let uuid = format!("{}", id.id.uuid);
        let typ = match entry {
            &DbEntry::KeyfileEntry { .. } => "keyfile",
            &DbEntry::PassphraseEntry { .. } => "passphrase",
            &DbEntry::YubikeyEntry { ref entry_type, .. } => match entry_type {
                &YubikeyEntryType::ChallengeResponse => "yubikey",
                &YubikeyEntryType::HybridChallengeResponse => "yubikey hybrid",
            },
        };

        let maybe_path = self.context
            .disk_uuid_path(&id.id.uuid)
            .ok()
            .and_then(|p| p.canonicalize().ok());

        let path_cell = maybe_path
            .as_ref()
            .map(|p| cell!(Fg -> p.to_string_lossy()))
            .unwrap_or(cell!(Fr -> "not present"));

        if self.only_available && maybe_path.is_none() {
            ()
        } else {
            // rows are: name,type,uuid,disk

            let row = table.add_row(row!(name, typ, uuid));
            row.add_cell(path_cell);
        }
    }
}
