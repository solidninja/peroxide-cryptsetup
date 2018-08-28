use std::path::PathBuf;

use peroxide_cryptsetup::context::{Context, PeroxideDbOps};
use peroxide_cryptsetup::db::{DbEntry, DbEntryType, VolumeId};
use peroxide_cryptsetup::device::LuksVolumeOps;

use operation::{path_or_uuid_to_path, OperationError, Result};

#[derive(Debug)]
pub struct Params {
    /// Device path or UUID (mix) vector
    pub device_paths_or_uuids: Vec<String>,
    /// Entry type to register (keyfile, passphrase, etc.)
    pub entry_type: DbEntryType,
    /// Key file path (optional)
    pub keyfile: Option<PathBuf>,
    /// Name to register with
    pub name: Option<String>,
}

pub fn register<C: Context>(ctx: &C, params: Params) -> Result<()> {
    let mut db = ctx.open_db()?;

    let entries = params
        .device_paths_or_uuids
        .iter()
        .map(|path_or| path_or_uuid_to_path(&path_or))
        .map(|p_res| p_res.and_then(|p| to_entry(p, &params)))
        .collect::<Result<Vec<_>>>()?;

    for entry in entries.into_iter() {
        db.entries.push(entry);
    }

    ctx.save_db(&db)?;
    Ok(())
}

fn to_entry(disk_path: PathBuf, params: &Params) -> Result<DbEntry> {
    let uuid = disk_path.uuid()?;
    let volume_id = VolumeId::new(params.name.clone(), uuid);

    match params.entry_type {
        DbEntryType::Keyfile => Ok(DbEntry::KeyfileEntry {
            volume_id,
            key_file: params.keyfile.clone().expect("Expected keyfile to be passed in"),
        }),
        DbEntryType::Passphrase => Ok(DbEntry::PassphraseEntry { volume_id }),
        other => Err(OperationError::ValidationFailed(format!(
            "Entry type {:?} not supported in register operation",
            other
        ))),
    }
}
