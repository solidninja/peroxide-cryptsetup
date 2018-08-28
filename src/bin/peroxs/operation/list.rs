use peroxide_cryptsetup::context::{Context, PeroxideDbOps};
use peroxide_cryptsetup::db::{DbEntry, YubikeyEntryType};
use prettytable::{format, Table};

use operation::{path_or_uuid_to_path, Result};

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
    let id = DbEntry::volume_id(entry);
    let name = id.name.clone().unwrap_or("".to_string());
    let uuid = format!("{}", id.uuid());
    let typ = match entry {
        &DbEntry::KeyfileEntry { .. } => "keyfile",
        &DbEntry::PassphraseEntry { .. } => "passphrase",
        &DbEntry::YubikeyEntry { ref entry_type, .. } => match entry_type {
            &YubikeyEntryType::ChallengeResponse => "yubikey",
            &YubikeyEntryType::HybridChallengeResponse => "yubikey hybrid",
        },
    };

    let maybe_path = path_or_uuid_to_path(&format!("{}", &id.uuid()))
        .ok()
        .and_then(|p| p.canonicalize().ok());

    let path_cell = maybe_path
        .as_ref()
        .map(|p| cell!(Fg -> p.to_string_lossy()))
        .unwrap_or(cell!(Fr -> "not present"));

    if params.only_available && maybe_path.is_none() {
        ()
    } else {
        // rows are: name,type,uuid,disk

        let row = table.add_row(row!(name, typ, uuid));
        row.add_cell(path_cell);
    }
}

// TODO - check active devices for name they are mapped with
