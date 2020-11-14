use peroxide_cryptsetup::context::{Context, PeroxideDbOps};
use peroxide_cryptsetup::db::{DbEntry, YubikeyEntryType};
use peroxide_cryptsetup::device::Disks;
use prettytable::{format, Table};

use crate::operation::Result;

#[derive(Debug)]
pub struct Params {
    /// Flag to list only available disks
    pub only_available: bool,
}

pub fn list<C: Context>(ctx: &C, params: Params) -> Result<()> {
    let db = ctx.open_db()?;

    // sort entries by name, then by uuid
    let mut entries = db.entries.clone();
    entries.sort_by_key(|entry| entry.volume_id().clone());

    let mut table = Table::new();
    table.add_row(row![b->"Name", b->"Type", b->"Uuid", b->"Disk"]);

    for entry in entries.iter() {
        add_table_entry(&params, &mut table, entry);
    }

    table.set_format(*format::consts::FORMAT_CLEAN);
    table.printstd();

    Ok(())
}

fn add_table_entry(params: &Params, table: &mut Table, entry: &DbEntry) -> () {
    let id = entry.volume_id();
    let name = id.name.clone().unwrap_or("".to_string());
    let uuid = id.uuid().to_string();
    let typ = match entry {
        &DbEntry::KeyfileEntry { .. } => "keyfile",
        &DbEntry::PassphraseEntry { .. } => "passphrase",
        &DbEntry::YubikeyEntry { ref entry_type, .. } => match entry_type {
            &YubikeyEntryType::ChallengeResponse => "yubikey",
            &YubikeyEntryType::HybridChallengeResponse => "yubikey hybrid",
        },
    };

    let path_opt = Disks::disk_uuid_path(id.uuid())
        .ok()
        .and_then(|p| p.canonicalize().ok());
    let path_cell = path_opt
        .as_ref()
        .map(|p| cell!(Fg -> p.to_string_lossy()))
        .unwrap_or(cell!(Fr -> "not present"));

    if params.only_available && path_opt.is_none() {
        ()
    } else {
        // rows are: name,type,uuid,disk

        let row = table.add_row(row!(name, typ, uuid));
        row.add_cell(path_cell);
    }
}

// TODO - check active devices for name they are mapped with
