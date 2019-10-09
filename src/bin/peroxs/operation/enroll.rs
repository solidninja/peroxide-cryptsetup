use std::path::PathBuf;

use peroxide_cryptsetup::context::{Context, DatabaseOps, DeviceOps, PeroxideDbOps};
use peroxide_cryptsetup::db::{DbEntry, DbEntryType, VolumeId, YubikeyEntryType, YubikeySlot};
use peroxide_cryptsetup::device::LuksVolumeOps;
use uuid::Uuid;

use crate::operation::{path_or_uuid_to_path, OperationError as Error, Result};

#[derive(Debug)]
pub struct NewContainerParameters {
    pub cipher: String,
    pub hash: String,
    pub key_bits: usize,
}

#[derive(Debug)]
pub struct Params<BC: Context + DeviceOps> {
    /// Entry type to enroll
    pub entry_type: DbEntryType,
    /// Parameters for formatting the disk if it's not already a LUKS container
    pub new_container: Option<NewContainerParameters>,
    /// List of device paths or UUIDs corresponding to the devices we want to enroll
    pub device_paths_or_uuids: Vec<String>,
    /// Number of iterations (in milliseconds)
    pub iteration_ms: usize,
    /// Key file to use
    pub keyfile: Option<PathBuf>,
    /// Backup context (if using a backup database)
    pub backup_context: Option<BC>,
    /// Name override (if a single device is present)
    pub name: Option<String>,
    /// Yubikey slot to use (if using the yubikey)
    pub yubikey_slot: Option<YubikeySlot>,
    /// Yubikey entry type to create
    pub yubikey_entry_type: Option<YubikeyEntryType>,
}

pub fn enroll<C: Context + DeviceOps, BC: Context + DeviceOps>(ctx: &C, params: Params<BC>) -> Result<()> {
    let mut db = ctx.open_db()?;

    let candidate_entries: Vec<(DbEntry, PathBuf)> = params
        .device_paths_or_uuids
        .iter()
        .map(|path_or| {
            let path = path_or_uuid_to_path(&path_or)?;
            match db.find_entry_for_disk_path(&path) {
                Some(entry) => Err(Error::ValidationFailed(format!(
                    "Found existing database entry {:?} for disk {}",
                    entry,
                    path.to_string_lossy()
                ))),
                None => make_entry(path, &params),
            }
        })
        .collect::<Result<Vec<_>>>()?;

    // check dups
    {
        let mut volume_ids: Vec<VolumeId> = candidate_entries.iter().map(|ep| ep.0.volume_id().clone()).collect();
        volume_ids.sort();
        volume_ids.dedup();
        if params.device_paths_or_uuids.len() > volume_ids.len() {
            return Err(Error::ValidationFailed(format!(
                "Duplicates found in disks specified, please enroll a disk only once"
            )));
        }
    }

    if candidate_entries.is_empty() {
        return Err(Error::ValidationFailed(format!("Cannot enroll 0 disks")));
    }

    // format containers, if not, enroll existing ones
    let enrolled_entries = if let Some(ref new_container) = params.new_container {
        format_containers(ctx, new_container, params.iteration_ms, candidate_entries)
    } else if let Some(ref backup_ctx) = params.backup_context {
        enroll_with_backup_context(ctx, backup_ctx, params.iteration_ms, candidate_entries)
    } else {
        enroll_all(ctx, params.iteration_ms, candidate_entries)
    }?;

    db.entries.extend(enrolled_entries);
    ctx.save_db(&db).map_err(From::from)
}

fn make_entry<BC: Context + DeviceOps>(path: PathBuf, params: &Params<BC>) -> Result<(DbEntry, PathBuf)> {
    let uuid_opt = path.uuid().ok();

    // if a uuid could be determined from path, this means disk is already formatted as luks
    if uuid_opt.is_some() && params.new_container.is_some() {
        return Err(Error::ValidationFailed(format!(
            "Disk at {} is already formatted",
            path.to_string_lossy()
        )));
    }

    let uuid = params
        .new_container
        .as_ref()
        .map(|_| Uuid::new_v4())
        .or(uuid_opt)
        .ok_or(Error::ValidationFailed(format!(
            "Not able to determine UUID for existing disk {}",
            path.to_string_lossy()
        )))?;

    let volume_id = VolumeId::new(params.name.clone(), uuid);

    let entry = match params.entry_type {
        DbEntryType::Keyfile => {
            if let Some(key_file) = params.keyfile.as_ref() {
                Ok(DbEntry::KeyfileEntry {
                    key_file: key_file.clone(),
                    volume_id,
                })
            } else {
                Err(Error::ValidationFailed(format!("No keyfile passed")))
            }
        }
        DbEntryType::Passphrase => Ok(DbEntry::PassphraseEntry { volume_id }),
        DbEntryType::Yubikey => match (params.yubikey_slot, params.yubikey_entry_type) {
            (Some(slot), Some(entry_type)) => Ok(DbEntry::YubikeyEntry {
                slot,
                entry_type,
                volume_id,
            }),
            _ => Err(Error::ValidationFailed(format!("No yubikey slot or entry type passed"))),
        },
    }?;

    Ok((entry, path))
}

fn format_containers<C: Context + DeviceOps>(
    ctx: &C,
    new_container: &NewContainerParameters,
    iteration_ms: usize,
    devices: Vec<(DbEntry, PathBuf)>,
) -> Result<Vec<DbEntry>> {
    // split cipher string by - e.g. 'aes-xts-plain' becomes 'aes' and 'xts-plain'
    let cipher_split: Vec<&str> = new_container.cipher.splitn(2, '-').collect();
    if cipher_split.len() != 2 {
        return Err(Error::ValidationFailed(format!(
            "Failed to split cipher spec '{}' into 2 parts",
            new_container.cipher.as_str()
        )));
    }
    let (cipher, cipher_mode) = (cipher_split[0], cipher_split[1]);

    let key = {
        let (first, _) = devices.first().expect("first entry");

        let prompt = if devices.len() == 1 {
            format!("Please enter new key for {}", first.volume_id())
        } else {
            format!("Please enter new key for multiple disks [{}, ...]", first.volume_id())
        };

        // prompt for key (same across devices)
        // FIXME - if we get key based on first device, then order matters for yubikey hybrid mode as it depends on uuid
        ctx.prompt_key(first, prompt)
    }?;

    devices
        .into_iter()
        .map(|entry_path| {
            let (entry, path) = entry_path;
            let _ = path.luks_format_with_key(
                iteration_ms,
                cipher,
                cipher_mode,
                new_container.hash.as_str(),
                new_container.key_bits,
                Some(entry.volume_id().uuid()),
                &key,
            )?;
            Ok(entry)
        })
        .collect::<Result<Vec<_>>>()
}

fn enroll_with_backup_context<C: Context + DeviceOps, BC: Context + DeviceOps>(
    ctx: &C,
    backup_ctx: &BC,
    iteration_ms: usize,
    devices: Vec<(DbEntry, PathBuf)>,
) -> Result<Vec<DbEntry>> {
    let backup_db = backup_ctx.open_db()?;
    let backup_entry_opt = backup_db.entries.iter().find(|entry| {
        devices
            .iter()
            .find(|device_path| device_path.0.uuid() == entry.uuid())
            .is_some()
    });

    if let Some(backup_entry) = backup_entry_opt {
        let backup_prompt = if devices.len() == 1 {
            format!("Please enter backup key for {}", backup_entry.volume_id())
        } else {
            format!(
                "Please enter backup key for multiple disks [{}, ...]",
                backup_entry.volume_id()
            )
        };

        let new_prompt = {
            let (first, _) = devices.first().expect("first entry");

            if devices.len() == 1 {
                format!("Please enter new key for {}", first.volume_id())
            } else {
                format!("Please enter new key for multiple disks [{}, ...]", first.volume_id())
            }
        };

        // backup entry, try to get key from that
        let backup_key = backup_ctx.prompt_key(backup_entry, backup_prompt)?;

        let new_key = {
            let (first, _) = devices.first().expect("first entry");
            ctx.prompt_key(first, new_prompt)?
        };

        devices
            .into_iter()
            .map(|entry_path| {
                let (entry, path) = entry_path;
                let _ = path.luks_add_key(iteration_ms, &new_key, &backup_key)?;
                Ok(entry)
            })
            .collect::<Result<Vec<_>>>()
    } else {
        // not found a backup entry, prompt as usual
        enroll_all(ctx, iteration_ms, devices)
    }
}

fn enroll_all<C: Context + DeviceOps>(
    ctx: &C,
    iteration_ms: usize,
    devices: Vec<(DbEntry, PathBuf)>,
) -> Result<Vec<DbEntry>> {
    let (first, _) = { devices.first().expect("first entry").clone() };

    // always default to passphrase entry
    let passphrase_entry = DbEntry::PassphraseEntry {
        volume_id: first.volume_id().clone(),
    };

    let prev_prompt = if devices.len() == 1 {
        format!("Please enter existing key for {}", first.volume_id())
    } else {
        format!(
            "Please enter existing key for multiple disks [{}, ...]",
            first.volume_id()
        )
    };

    let new_prompt = if devices.len() == 1 {
        format!("Please enter new key for {}", first.volume_id())
    } else {
        format!("Please enter new key for multiple disks [{}, ...]", first.volume_id())
    };

    let prev_key = ctx.prompt_key(&passphrase_entry, prev_prompt)?;
    let new_key = ctx.prompt_key(&first, new_prompt)?;

    devices
        .into_iter()
        .map(|entry_path| {
            let (entry, path) = entry_path;
            let _ = path.luks_add_key(iteration_ms, &new_key, &prev_key)?;
            Ok(entry)
        })
        .collect::<Result<Vec<_>>>()
}

// TODO test for behavior where keyfile is no inside the directory of the db
