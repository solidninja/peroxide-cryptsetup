use std::path::{Path, PathBuf};

use cryptsetup_rs;
use uuid;

use io::{FileExtensions, KeyWrapper};
use model::{DbEntry, DbEntryType, VolumeId};
use operation::{
    EnrollOperation, LuksDevice, NewContainerParameters, OperationError, PasswordPromptString, PerformCryptOperation,
    Result, UserDiskLookup,
};

use context;
use context::{InputContext, ReaderContext, WriterContext};

impl<Context, BackupContext> PerformCryptOperation for EnrollOperation<Context, BackupContext>
where
    Context: WriterContext + InputContext,
    BackupContext: ReaderContext + InputContext,
{
    fn apply(&self) -> Result<()> {
        self.validate_entry_constraints()?;
        let device_paths = self.lookup_device_paths()?;
        let devices = self.create_or_format_devices(&device_paths)?;
        let devices_with_entries = devices
            .into_iter()
            .map(|device| {
                let entry = self.get_preexisting_entry(&device);
                (device, entry)
            })
            .collect();
        self.enroll_devices_with_entries(devices_with_entries)
    }
}

impl<Context, BackupContext> EnrollOperation<Context, BackupContext>
where
    Context: WriterContext + InputContext,
    BackupContext: ReaderContext + InputContext,
{
    // TODO common functionality
    fn lookup_device_paths(&self) -> Result<Vec<PathBuf>> {
        // TODO - same comment in register.rs - better way to convert Vec<String> -> &[&str]
        let device_paths_or_uuids: Vec<&str> = self.device_paths_or_uuids.iter().map(|s| s.as_ref()).collect();
        // killed by the ::<>
        let mut device_map = self.context.resolve_paths_or_uuids(&device_paths_or_uuids);
        let res = device_map.drain().map(|kv| kv.1).collect::<context::Result<Vec<_>>>()?;
        Ok(res)
    }

    fn validate_entry_constraints(&self) -> Result<()> {
        let db_loc = self.context.db_location();

        match self.entry_type {
            DbEntryType::Keyfile if self.device_paths_or_uuids.len() > 1 => Err(OperationError::ValidationFailed(
                "Multiple devices should not have the same key file".to_string(),
            )),
            _ => Ok(()),
        }?;

        match self.entry_type {
            DbEntryType::Keyfile => {
                let keyfile = self.keyfile.as_ref().unwrap();
                db_loc
                    .relative_path(keyfile)
                    .ok_or_else(|| {
                        OperationError::ValidationFailed(format!(
                            "The database directory did not contain the key file '{}'",
                            keyfile.display()
                        ))
                    })
                    .map(|_| ())
            }
            _ => Ok(()),
        }?;

        Ok(())
    }

    fn create_or_format_devices<P: AsRef<Path>>(
        &self,
        device_paths: &[P],
    ) -> Result<Vec<cryptsetup_rs::Luks1CryptDeviceHandle>> {
        device_paths
            .iter()
            .map(|path| match self.new_container {
                Some(ref new_container) => self.format_container(new_container, path),
                None => self.open_container(path),
            })
            .collect()
    }

    fn open_container<P: AsRef<Path>>(&self, path: P) -> Result<cryptsetup_rs::Luks1CryptDeviceHandle> {
        let device = cryptsetup_rs::open(path.as_ref())
            .and_then(|open| open.luks1())
            .map_err(|err| (path.as_ref(), err))?;
        Ok(device)
    }

    fn format_container<P: AsRef<Path>>(
        &self,
        params: &NewContainerParameters,
        path: P,
    ) -> Result<cryptsetup_rs::Luks1CryptDeviceHandle> {
        let cipher_split: Vec<&str> = params.cipher.splitn(2, '-').collect();
        // TODO - better error handling if it cannot be split
        assert_eq!(cipher_split.len(), 2);

        let device = cryptsetup_rs::format(path.as_ref())
            .and_then(|format| format.luks1(cipher_split[0], cipher_split[1], &params.hash, params.key_bits, None))
            .map_err(|err| (path.as_ref(), err))?;

        Ok(device)
    }

    fn get_preexisting_entry(&self, device: &LuksDevice) -> Option<DbEntry> {
        if self.new_container.is_some() {
            // don't support partial formatting - it's either all or nothing
            None
        } else {
            // if there is no backup db or backup db open/lookup failed, use a passphrase entry
            self.backup_context
                .as_ref()
                .and_then(|ctx| ctx.open_peroxide_db().ok())
                .and_then(|db| {
                    // TODO: again, code dup finding entries
                    db.entries
                        .iter()
                        .find(|e| e.uuid() == &device.uuid())
                        .map(|e| e.clone())
                })
                .or_else(|| {
                    Some(DbEntry::PassphraseEntry {
                        volume_id: VolumeId::new(None, device.uuid()),
                    })
                })
        }
    }

    fn enroll_devices_with_entries(
        &self,
        devices_with_entries: Vec<(cryptsetup_rs::Luks1CryptDeviceHandle, Option<DbEntry>)>,
    ) -> Result<()> {
        let mut db = self.context
            .open_peroxide_db()
            .map_err(|_| OperationError::DbOpenFailed)?;

        let enroll_device = |cd: &mut LuksDevice, entry: Option<&DbEntry>| {
            let uuid = cd.uuid();
            let volume_id = VolumeId::new(self.name.clone(), uuid);

            // get keys
            let maybe_previous_key = self.get_previous_key_wrapper(entry)?;
            let new_key = self.get_new_key_wrapper(&uuid)?;

            // set parameters
            cd.set_iteration_time(self.iteration_ms as u64);

            // enroll
            cd.add_keyslot(
                new_key.as_slice(),
                maybe_previous_key.as_ref().map(|k| k.as_slice()),
                None,
            ).map_err(|e| (cd.path(), e))?;

            // create db entry
            Ok(self.create_new_entry(volume_id))
        };

        let mut devs = devices_with_entries; // FIXME mutability hack
        let new_entries = devs.iter_mut()
            .map(|&mut (ref mut device, ref mut entry)| enroll_device(device, entry.as_ref()))
            .collect::<Result<Vec<_>>>()?;

        // add all entries and save
        db.entries.extend(new_entries);
        self.context
            .save_peroxide_db(&db)
            .map_err(|_| OperationError::DbSaveFailed)
    }

    fn get_previous_key_wrapper(&self, entry: Option<&DbEntry>) -> Result<Option<KeyWrapper>> {
        entry
            .map(|previous_entry| {
                match previous_entry {
                    &DbEntry::PassphraseEntry { ref volume_id } => {
                        self.context.read_password(&volume_id.prompt_string())
                    }
                    &DbEntry::KeyfileEntry { ref key_file, .. } => self.backup_context
                        .as_ref()
                        .map(|ctx| ctx.read_keyfile(&key_file))
                        .unwrap(),
                    &DbEntry::YubikeyEntry {
                        ref slot,
                        ref entry_type,
                        ref volume_id,
                    } => self.backup_context
                        .as_ref()
                        .map(|ctx| {
                            ctx.read_yubikey(
                                Some(&volume_id.prompt_name()),
                                &volume_id.id.uuid,
                                slot.clone(),
                                entry_type.clone(),
                            )
                        })
                        .unwrap(),
                }.map_err(OperationError::from)
                    .map(|k| Some(k))
            })
            .unwrap_or(Ok(None))
    }

    fn get_new_key_wrapper(&self, uuid: &uuid::Uuid) -> Result<KeyWrapper> {
        match self.entry_type {
            DbEntryType::Passphrase => self.context.read_password("Please enter new passphrase:"),
            DbEntryType::Keyfile => self.keyfile
                .as_ref()
                .map(|keyfile| self.context.read_keyfile(keyfile))
                .unwrap(),
            DbEntryType::Yubikey => self.context.read_yubikey(
                None,
                uuid,
                self.yubikey_slot.as_ref().unwrap().clone(),
                self.yubikey_entry_type.as_ref().unwrap().clone(),
            ),
        }.map_err(OperationError::from)
    }

    fn create_new_entry(&self, volume_id: VolumeId) -> DbEntry {
        match self.entry_type {
            DbEntryType::Passphrase => DbEntry::PassphraseEntry { volume_id },
            DbEntryType::Keyfile => DbEntry::KeyfileEntry {
                key_file: self.keyfile.as_ref().unwrap().clone(),
                volume_id,
            },
            DbEntryType::Yubikey => DbEntry::YubikeyEntry {
                slot: self.yubikey_slot.as_ref().unwrap().clone(),
                entry_type: self.yubikey_entry_type.as_ref().unwrap().clone(),
                volume_id,
            },
        }
    }
}
