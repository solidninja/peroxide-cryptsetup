use cryptsetup_rs::device::{CryptDevice, crypt_device_type};

use uuid;

use operation::{PerformCryptOperation, EnrollOperation, OperationError, UserDiskLookup, Result, PasswordPromptString,
                ApplyCryptDeviceOptions};
use model::{DbEntryType, DbEntry, VolumeId};
use io::{FileExtensions, KeyWrapper};
use context::{WriterContext, ReaderContext, InputContext, DiskSelector};

impl<Context, BackupContext> PerformCryptOperation for EnrollOperation<Context, BackupContext>
    where Context: WriterContext + InputContext + DiskSelector + ApplyCryptDeviceOptions,
          BackupContext: ReaderContext + InputContext
{
    fn apply(&self) -> Result<()> {
        try!(self.validate_entry_constraints());
        let mut devices = try!(self.context.lookup_devices(&self.device_paths_or_uuids));
        try!(self.create_new_containers(&mut devices));
        let devices_with_entries = devices.into_iter()
            .map(|device| {
                let entry = self.get_preexisting_entry(&device);
                (device, entry)
            })
            .collect::<Vec<_>>();
        self.enroll_devices_with_entries(devices_with_entries)
    }
}


impl<Context, BackupContext> EnrollOperation<Context, BackupContext>
    where Context: WriterContext + InputContext + DiskSelector + ApplyCryptDeviceOptions,
          BackupContext: ReaderContext + InputContext
{
    fn validate_entry_constraints(&self) -> Result<()> {
        let db_loc = self.context.db_location();

        try!(match self.entry_type {
            DbEntryType::Keyfile if self.device_paths_or_uuids.len() > 1 => {
                Err(OperationError::ValidationFailed("Multiple devices should not have the same key file".to_string()))
            }
            _ => Ok(()),
        });

        try!(match self.entry_type {
            DbEntryType::Keyfile => {
                let keyfile = self.keyfile.as_ref().unwrap();
                db_loc.relative_path(keyfile)
                    .ok_or_else(|| {
                        OperationError::ValidationFailed(format!("The database directory did not contain the key file '{}'",
                                                                 keyfile.display()))
                    })
                    .map(|_| ())
            }
            _ => Ok(()),
        });

        Ok(())
    }

    fn create_new_containers(&self, devices: &mut [CryptDevice]) -> Result<()> {
        let create_container = |crypt_device: &mut CryptDevice| {
            self.new_container
                .as_ref()
                .map(|params| {
                    if crypt_device.load(crypt_device_type::LUKS1).is_ok() {
                        Err(OperationError::ValidationFailed(format!("Device '{}' is already formatted and cannot be formatted again",
                                                                     crypt_device.path.to_str().unwrap())))
                    } else {
                        let cipher_split: Vec<&str> = params.cipher.splitn(2, '-').collect();
                        // TODO - better error handling if it cannot be split
                        assert!(cipher_split.len() == 2);

                        crypt_device.format_luks(cipher_split[0],
                                         cipher_split[1],
                                         &params.hash,
                                         params.key_bits,
                                         None)
                            .map_err(|err| From::from((crypt_device.path.as_path(), err)))
                    }
                })
                .unwrap_or(Ok(()))
        };

        devices.iter_mut()
            .map(create_container)
            .collect::<Result<Vec<_>>>()
            .map(|_| ())  // TODO better?
    }

    fn get_preexisting_entry(&self, device: &CryptDevice) -> Option<DbEntry> {
        if self.new_container.is_some() {
            None
        } else {
            device.load(crypt_device_type::LUKS1).unwrap();
            // if there is no backup db or backup db open/lookup failed, use a passphrase entry
            self.backup_context
                .as_ref()
                .and_then(|ctx| ctx.open_peroxide_db().ok())
                .and_then(|db| {
                    db.entries
                        .iter()
                        .find(|e| e.uuid() == &device.uuid().unwrap())
                        .map(|e| e.clone())
                })
                .or_else(|| Some(DbEntry::PassphraseEntry { volume_id: VolumeId::new(None, device.uuid().unwrap().clone()) }))
        }
    }

    fn enroll_devices_with_entries(&self, devices_with_entries: Vec<(CryptDevice, Option<DbEntry>)>) -> Result<()> {
        let mut db = try!(self.context.open_peroxide_db().map_err(|_| OperationError::DbOpenFailed));

        let enroll_device = |cd: &mut CryptDevice, entry: Option<&DbEntry>| {
            let uuid = try!(cd.uuid().ok_or(OperationError::CryptOperationFailed(cd.path.clone(), "Unable to load uuid".to_string())));
            let volume_id = VolumeId::new(self.name.clone(), uuid);

            // get keys
            let maybe_previous_key = try!(self.get_previous_key_wrapper(entry));
            let new_key = try!(self.get_new_key_wrapper(&uuid));

            // set parameters
            cd.set_iteration_time(self.iteration_ms as u64);

            // enroll
            try!(cd.add_keyslot(new_key.as_slice(),
                             maybe_previous_key.as_ref().map(|k| k.as_slice()),
                             None)
                .map_err(|e| OperationError::from((&cd.path, e))));

            // create db entry
            Ok(self.create_new_entry(volume_id))
        };

        let mut devs = devices_with_entries;  // FIXME mutability hack
        let new_entries = try!(devs.iter_mut()
            .map(|&mut (ref mut device, ref mut entry)| enroll_device(device, entry.as_ref()))
            .collect::<Result<Vec<_>>>());

        // add all entries and save
        db.entries.extend(new_entries);
        self.context.save_peroxide_db(&db).map_err(|_| OperationError::DbSaveFailed)
    }

    fn get_previous_key_wrapper(&self, entry: Option<&DbEntry>) -> Result<Option<KeyWrapper>> {
        entry.map(|previous_entry| {
                match previous_entry {
                        &DbEntry::PassphraseEntry { ref volume_id } => self.context.read_password(&volume_id.prompt_string()),
                        &DbEntry::KeyfileEntry { ref key_file, .. } => {
                            self.backup_context.as_ref().map(|ctx| ctx.read_keyfile(&key_file)).unwrap()
                        }
                        &DbEntry::YubikeyEntry { ref slot, ref entry_type, ref volume_id } => {
                            self.backup_context
                                .as_ref()
                                .map(|ctx| {
                                    ctx.read_yubikey(Some(&volume_id.prompt_name()),
                                                     &volume_id.id.uuid,
                                                     slot.clone(),
                                                     entry_type.clone())
                                })
                                .unwrap()
                        }
                    }
                    .map_err(OperationError::from)
                    .map(|k| Some(k))
            })
            .unwrap_or(Ok(None))
    }

    fn get_new_key_wrapper(&self, uuid: &uuid::Uuid) -> Result<KeyWrapper> {
        match self.entry_type {
                DbEntryType::Passphrase => self.context.read_password("Please enter new passphrase:"),
                DbEntryType::Keyfile => self.keyfile.as_ref().map(|keyfile| self.context.read_keyfile(keyfile)).unwrap(),
                DbEntryType::Yubikey => {
                    self.context.read_yubikey(None,
                                              uuid,
                                              self.yubikey_slot.as_ref().unwrap().clone(),
                                              self.yubikey_entry_type.as_ref().unwrap().clone())
                }
            }
            .map_err(OperationError::from)
    }

    fn create_new_entry(&self, volume_id: VolumeId) -> DbEntry {
        match self.entry_type {
            DbEntryType::Passphrase => DbEntry::PassphraseEntry { volume_id: volume_id },
            DbEntryType::Keyfile => {
                DbEntry::KeyfileEntry {
                    key_file: self.keyfile.as_ref().unwrap().clone(),
                    volume_id: volume_id,
                }
            }
            DbEntryType::Yubikey => {
                DbEntry::YubikeyEntry {
                    slot: self.yubikey_slot.as_ref().unwrap().clone(),
                    entry_type: self.yubikey_entry_type.as_ref().unwrap().clone(),
                    volume_id: volume_id,
                }
            }
        }
    }
}
