use std::path::PathBuf;

use snafu::prelude::*;

use peroxide_cryptsetup::context::{Context, PeroxideDbOps};
use peroxide_cryptsetup::db::{DbEntry, DbEntryType, VolumeId};
use peroxide_cryptsetup::device::LuksVolumeOps;

use crate::operation::{ContextSnafu, DeviceSnafu, PathOrUuid, Result, ValidationSnafu};

#[derive(Debug)]
pub struct Params {
    /// Device path or UUID (mix) vector
    pub device_paths_or_uuids: Vec<PathOrUuid>,
    /// Entry type to register (keyfile, passphrase, etc.)
    pub entry_type: DbEntryType,
    /// Key file path (optional)
    pub keyfile: Option<PathBuf>,
    /// Name to register with
    pub name: Option<String>,
}

pub fn register<C: Context>(ctx: &C, params: Params) -> Result<()> {
    let mut db = ctx.open_db().context(ContextSnafu)?;

    let entries = params
        .device_paths_or_uuids
        .iter()
        .map(|p| p.to_path().and_then(|p| to_entry(p, &params)))
        .collect::<Result<Vec<_>>>()?;

    for entry in entries.into_iter() {
        db.entries.push(entry);
    }

    ctx.save_db(&db).context(ContextSnafu)?;
    Ok(())
}

fn to_entry(disk_path: PathBuf, params: &Params) -> Result<DbEntry> {
    let uuid = disk_path.luks_uuid().context(DeviceSnafu)?;
    let volume_id = VolumeId::of(params.name.clone(), uuid);

    match params.entry_type {
        DbEntryType::Keyfile => Ok(DbEntry::KeyfileEntry {
            volume_id,
            key_file: params.keyfile.clone().expect("Expected keyfile to be passed in"),
        }),
        DbEntryType::Passphrase => Ok(DbEntry::PassphraseEntry { volume_id }),
        other => Err(ValidationSnafu {
            message: format!("Entry type {:?} not supported in register operation", other),
        }
        .build()),
    }
}
