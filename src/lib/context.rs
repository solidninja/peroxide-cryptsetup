use std::path::{Path, PathBuf};
use std::result;
use std::time::Duration;

use cryptsetup_rs;

pub use cryptsetup_rs::Luks1CryptDeviceHandle as Luks1Device;

use secstr::SecStr;
use vec1::Vec1;

use crate::db::{DbEntry, Error as DbError, PeroxideDb, VolumeId, YubikeyEntryType, YubikeySlot};
use crate::device::{Disks, Error as DeviceError, LuksVolumeOps};
use crate::input::{get_key_for, BackupPrompt, Error as InputError, KeyInputConfig};
use uuid::Uuid;

pub type Result<T> = result::Result<T, Error>;

pub type DeviceMapperName = String;

#[derive(Debug)]
pub enum Error {
    DatabaseError(DbError),
    DeviceAlreadyActivated(String),
    DeviceAlreadyFormatted(Uuid),
    NotAllDisksAlreadyFormatted,
    DiskIdDuplicatesFound,
    EntryAlreadyExists(Uuid),
    DiskEntryNotFound(Uuid),
    DeviceError(DeviceError),
    FeatureNotAvailable,
    KeyInputError(InputError),
    VolumeNotFound(VolumeId),
}

impl From<DbError> for Error {
    fn from(e: DbError) -> Self {
        Error::DatabaseError(e)
    }
}

impl From<DeviceError> for Error {
    fn from(e: DeviceError) -> Self {
        Error::DeviceError(e)
    }
}

impl From<InputError> for Error {
    fn from(e: InputError) -> Self {
        Error::KeyInputError(e)
    }
}

pub trait Context {
    fn db_location(&self) -> &Path;
}

impl Context for MainContext {
    fn db_location(&self) -> &Path {
        self.db_path.as_ref()
    }
}

#[derive(Debug, Clone)]
pub enum FormatContainerParams {
    Luks1 {
        iteration_ms: u32,
        cipher: String,
        cipher_mode: String,
        hash: String,
        mk_bits: usize,
    },
    Luks2 {
        cipher: String,
        cipher_mode: String,
        mk_bits: usize,
        hash: String,
        time_ms: u32,
        iterations: u32,
        max_memory_kb: u32,
        parallel_threads: u32,
        sector_size: Option<u32>,
        data_alignment: Option<u32>,
        save_label_in_header: bool,
    },
}

#[derive(Debug, Clone)]
pub enum EntryParams {
    Keyfile(PathBuf),
    Passphrase,
    Yubikey(YubikeySlot, YubikeyEntryType),
}

#[derive(Debug, Clone)]
pub struct DiskEnrolmentParams {
    pub name: Option<String>,
    pub entry: EntryParams,
    pub format_container: Option<FormatContainerParams>,
    pub force_format: bool,
    pub iteration_ms: u32, // TODO: try to remove this from here
}

pub trait PeroxideDbOps {
    fn open_db(&self) -> Result<PeroxideDb>;
    fn save_db(&self, db: &PeroxideDb) -> Result<()>;
}

impl<C: Context> PeroxideDbOps for C {
    fn open_db(&self) -> Result<PeroxideDb> {
        PeroxideDb::open_at(self.db_location()).map_err(From::from)
    }

    fn save_db(&self, db: &PeroxideDb) -> Result<()> {
        db.save_to(self.db_location()).map_err(From::from)
    }
}

fn entry_from(volume_id: VolumeId, params: EntryParams) -> DbEntry {
    match params {
        EntryParams::Passphrase => DbEntry::PassphraseEntry { volume_id },
        EntryParams::Keyfile(key_file) => DbEntry::KeyfileEntry { key_file, volume_id },
        EntryParams::Yubikey(slot, entry_type) => DbEntry::YubikeyEntry {
            entry_type,
            slot,
            volume_id,
        },
    }
}

fn format_container<P: AsRef<Path>>(
    disk_path: &P,
    entry: &DbEntry,
    params: &FormatContainerParams,
    key: &SecStr,
) -> Result<u8> {
    match params {
        FormatContainerParams::Luks1 {
            iteration_ms,
            cipher,
            cipher_mode,
            hash,
            mk_bits,
        } => disk_path
            .luks1_format_with_key(
                *iteration_ms as usize,
                &cipher,
                &cipher_mode,
                &hash,
                *mk_bits,
                Some(&entry.uuid()),
                key,
            )
            .map_err(From::from),
        FormatContainerParams::Luks2 {
            cipher,
            cipher_mode,
            mk_bits,
            hash,
            time_ms,
            iterations,
            max_memory_kb,
            parallel_threads,
            sector_size,
            data_alignment,
            save_label_in_header,
        } => {
            let label_opt = if *save_label_in_header {
                entry.volume_id().name.as_ref().map(|s| s.as_ref())
            } else {
                None
            };

            disk_path
                .luks2_format_with_key(
                    cipher,
                    cipher_mode,
                    *mk_bits,
                    hash,
                    *time_ms,
                    *iterations,
                    *max_memory_kb,
                    *parallel_threads,
                    *sector_size,
                    *data_alignment,
                    Some(entry.uuid()),
                    label_opt,
                    key,
                )
                .map_err(From::from)
        }
    }
}

fn prompt_old_key<Ctx: DeviceOps, BCtx: DeviceOps>(
    ctx: &Ctx,
    backup_db: Option<BackupPrompt<BCtx>>,
    volume_id: &VolumeId,
) -> Result<SecStr> {
    if let Some(bc) = backup_db {
        bc.prompt_key(volume_id.uuid()).map_err(From::from)
    } else {
        let passphrase_entry = DbEntry::PassphraseEntry {
            volume_id: volume_id.clone(),
        };
        ctx.prompt_key(&passphrase_entry, None, false)
    }
}

fn prompt_new_key<Ctx: DeviceOps>(ctx: &Ctx, entry: &DbEntry) -> Result<SecStr> {
    ctx.prompt_key(&entry, None, true)
}

pub trait DeviceOps {
    /// Activate a single disk and prompt for the key
    fn activate<P: AsRef<Path>>(
        &self,
        entry: &DbEntry,
        name_override: Option<String>,
        path_override: Option<P>,
    ) -> Result<DeviceMapperName>;

    /// Active a disk with a given key
    fn activate_with_key<P: AsRef<Path>>(
        &self,
        entry: &DbEntry,
        key: &SecStr,
        name_override: Option<String>,
        path_override: Option<P>,
    ) -> Result<DeviceMapperName>;

    /// Prompt for a key with a custom prompt
    fn prompt_key(&self, entry: &DbEntry, prompt_override: Option<String>, is_new: bool) -> Result<SecStr>;

    /// Enroll a new or existing LUKS disk with the given parameters
    fn enroll_disk<P: AsRef<Path>, BCtx: DeviceOps>(
        &self,
        db: &mut PeroxideDb,
        disk_path: P,
        params: DiskEnrolmentParams,
        backup_db: Option<BackupPrompt<BCtx>>,
    ) -> Result<DbEntry>;

    /// Enroll a set of new or existing LUKS disks with the given parameters
    fn enroll_disks<P: AsRef<Path>, BCtx: DeviceOps>(
        &self,
        db: &mut PeroxideDb,
        paths: Vec1<P>,
        params: DiskEnrolmentParams,
        backup_db: Option<BackupPrompt<BCtx>>,
    ) -> Result<Vec1<DbEntry>>;

    fn open_disks<P: AsRef<Path>>(
        &self,
        db: &PeroxideDb,
        paths: Vec1<P>,
        name_override: Option<String>,
    ) -> Result<Vec1<DeviceMapperName>>;
}

impl DeviceOps for MainContext {
    fn activate<P: AsRef<Path>>(
        &self,
        entry: &DbEntry,
        name_override: Option<String>,
        path_override: Option<P>,
    ) -> Result<DeviceMapperName> {
        let key = get_key_for(
            entry,
            &self.key_input_config,
            &self.db_path.parent().expect("parent path"),
            name_override.clone(),
            None,
            false,
        )?;
        self.activate_with_key(entry, &key, name_override, path_override)
    }

    fn activate_with_key<P: AsRef<Path>>(
        &self,
        entry: &DbEntry,
        key: &SecStr,
        name_override: Option<String>,
        path_override: Option<P>,
    ) -> Result<DeviceMapperName> {
        let name = name_override
            .or(entry.volume_id().name.clone())
            .unwrap_or_else(|| format!("uuid_{}", entry.volume_id().uuid()));

        if Disks::is_device_mapped(name.as_str()) {
            return Err(Error::DeviceAlreadyActivated(name));
        }

        let default_path = Disks::disk_uuid_path(entry.volume_id().uuid()).ok();
        // lim count(as_ref) -> ∞
        let path_opt = path_override
            .as_ref()
            .map(|p| p.as_ref())
            .or(default_path.as_ref().map(|p| p.as_ref()));

        if let Some(device_path) = path_opt {
            device_path
                .luks_activate(name.as_str(), key)
                .map(move |_| name)
                .map_err(From::from)
        } else {
            Err(Error::VolumeNotFound(entry.volume_id().clone()))
        }
    }

    fn prompt_key(&self, entry: &DbEntry, prompt_override: Option<String>, is_new: bool) -> Result<SecStr> {
        get_key_for(
            entry,
            &self.key_input_config,
            &self.db_path.parent().expect("parent path"),
            None,
            prompt_override,
            is_new,
        )
        .map_err(From::from)
    }

    fn enroll_disk<P: AsRef<Path>, BCtx: DeviceOps>(
        &self,
        db: &mut PeroxideDb,
        disk_path: P,
        params: DiskEnrolmentParams,
        backup_db: Option<BackupPrompt<BCtx>>,
    ) -> Result<DbEntry> {
        self.enroll_disks(db, Vec1::new(disk_path), params, backup_db)
            .map(|ve| ve.first().clone())
    }

    fn enroll_disks<P: AsRef<Path>, BCtx: DeviceOps>(
        &self,
        db: &mut PeroxideDb,
        paths: Vec1<P>,
        params: DiskEnrolmentParams,
        backup_db: Option<BackupPrompt<BCtx>>,
    ) -> Result<Vec1<DbEntry>> {
        let path_count = paths.len();
        let paths_with_existing_uuids = paths.mapped(|p| {
            let uuid_opt = p.luks_uuid().ok();
            (p, uuid_opt)
        });

        let mut count_formatted = 0usize;
        for (_, uuid_opt) in paths_with_existing_uuids.iter() {
            if let Some(uuid) = uuid_opt {
                if db.entry_exists(uuid) {
                    // validate: entry cannot exist twice
                    return Err(Error::EntryAlreadyExists(uuid.clone()));
                } else if params.format_container.is_some() && !params.force_format {
                    // validate: container should not be already formatted
                    return Err(Error::DeviceAlreadyFormatted(uuid.clone()));
                }
                count_formatted += 1;
            }
        }

        if params.format_container.is_none() && count_formatted != path_count {
            // validate: all containers should be formatted
            return Err(Error::NotAllDisksAlreadyFormatted);
        }

        let paths_with_volume_ids = paths_with_existing_uuids.mapped(|(p, uuid_opt)| {
            // don't give the same name to all the disks if len(disks) > 1
            let name_opt = if path_count == 1 { params.name.clone() } else { None };
            (
                p,
                VolumeId::of(name_opt, uuid_opt.clone().unwrap_or_else(|| Uuid::new_v4())),
            )
        });

        {
            // validate: all uuids should be unique
            let mut volume_ids = paths_with_volume_ids.iter().map(|e| e.1.clone()).collect::<Vec<_>>();
            volume_ids.sort();
            volume_ids.dedup();

            if path_count > volume_ids.len() {
                return Err(Error::DiskIdDuplicatesFound);
            }
        }

        // Enrollment in 3 steps:
        // 1. (optional) format the luks container
        // 2. prompt for old/new key(s)
        // 3. add the entry to the db

        let entries_with_path =
            paths_with_volume_ids.mapped(|(p, volume_id)| (p, entry_from(volume_id, params.entry.clone())));
        // TODO: first entry is used for all the enrollment, this matters especially for Yubikey UUID handling as it's order dependent
        let first_entry = &entries_with_path.first().1;

        let _keyslots = if let Some(ref format_params) = params.format_container {
            let new_key = prompt_new_key(self, first_entry)?;
            entries_with_path
                .try_mapped_ref(|(disk_path, entry)| format_container(disk_path, &entry, &format_params, &new_key))?
        } else {
            let prev_key = prompt_old_key(self, backup_db, first_entry.volume_id())?;
            let new_key = prompt_new_key(self, first_entry)?;

            entries_with_path.try_mapped_ref(|(disk_path, _)| {
                (*disk_path) // FIXME luks2
                    .luks1_add_key(params.iteration_ms as usize, &new_key, &prev_key)
                    .map_err::<Error, _>(From::from)
            })?
        };

        let entries = entries_with_path.mapped(|e| e.1);
        db.entries.extend_from_slice(entries.as_slice());
        // todo: should we save here too?
        self.save_db(&db)?;

        Ok(entries)
    }

    fn open_disks<P: AsRef<Path>>(
        &self,
        db: &PeroxideDb,
        paths: Vec1<P>,
        name_override: Option<String>,
    ) -> Result<Vec1<DeviceMapperName>> {
        let paths_with_uuid = paths.try_mapped(|p| p.luks_uuid().map(|uuid| (p, uuid)))?;
        let uuids = {
            let mut uuids = paths_with_uuid.mapped_ref(|pu| pu.1.to_owned());
            uuids.sort();
            uuids.dedup();
            uuids
        };

        if uuids.len() != paths_with_uuid.len() {
            return Err(Error::DiskIdDuplicatesFound);
        }

        let paths_with_disk_entries = paths_with_uuid.try_mapped(|pu| match db.find_entry(&pu.1) {
            Some(entry) => Ok((pu.0, entry)),
            None => Err(Error::DiskEntryNotFound(pu.1.clone())),
        })?;

        if paths_with_disk_entries.len() == 1 {
            let ((first_path, first_entry), _) = paths_with_disk_entries.split_off_first();
            self.activate(first_entry, name_override, Some(first_path))
                .map(Vec1::new)
        } else {
            // activate all the entries with the first key
            // todo: document that this means yubikey disks have all the same key (because tied to uuid of the disk)
            let key = self.prompt_key(&paths_with_disk_entries.first().1, None, false)?;

            let res = paths_with_disk_entries
                .into_iter()
                .enumerate()
                .map(|(idx, (path, db_entry))| {
                    // if override name is provided, all disks will start with the same prefix and will be identified by index
                    let name = name_override.as_ref().map(|name| format!("{}_{}", name, idx));
                    self.activate_with_key(&db_entry, &key, name, Some(path))
                })
                .collect::<Result<Vec<DeviceMapperName>>>()?;

            Ok(Vec1::try_from_vec(res).expect("non-empty vec"))
        }
    }
}

pub trait DatabaseOps {
    /// Check if an entry exists by uuid
    fn entry_exists(&self, uuid: &uuid::Uuid) -> bool;

    /// Find an entry by uuid
    fn find_entry(&self, uuid: &uuid::Uuid) -> Option<&DbEntry>;
}

impl DatabaseOps for PeroxideDb {
    fn entry_exists(&self, uuid: &uuid::Uuid) -> bool {
        self.find_entry(uuid).is_some()
    }

    fn find_entry(&self, uuid: &uuid::Uuid) -> Option<&DbEntry> {
        self.entries.iter().find(|e| e.volume_id().uuid() == uuid)
    }
}

#[derive(Debug)]
pub struct MainContext {
    pub db_path: PathBuf,
    pub key_input_config: KeyInputConfig,
}

impl MainContext {
    pub fn new(db_path: PathBuf) -> MainContext {
        MainContext {
            db_path,
            key_input_config: KeyInputConfig {
                password_input_timeout: Some(Duration::new(30, 0)),
            },
        }
    }

    pub fn trace_on() {
        cryptsetup_rs::enable_debug(true);
    }
}
