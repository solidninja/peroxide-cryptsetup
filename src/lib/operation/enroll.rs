use cryptsetup_rs::device::{CryptDevice, crypt_device_type};

use uuid;

use operation::{PerformCryptOperation, EnrollOperation, OperationError, UserDiskLookup, Result, PasswordPromptString};
use model::{DbEntryType, DbEntry, VolumeId};
use io::{FileExtensions, KeyWrapper};
use context::{WriterContext, ReaderContext, InputContext, HasDbLocation, KeyfileInput, PasswordInput, PeroxideDbReader, PeroxideDbWriter,
              DiskSelector};

impl<Context, BackupContext> PerformCryptOperation for EnrollOperation<Context, BackupContext>
    where Context: WriterContext + InputContext + DiskSelector,
          BackupContext: ReaderContext + InputContext
{
    fn apply(self) -> Result<()> {
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
    where Context: WriterContext + InputContext + DiskSelector,
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
            // FIXME remove unimplemented!()
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
                     &DbEntry::YubikeyEntry { ref slot, ref entry_type, ref volume_id} => {
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

#[cfg(test)]
mod tests {
    // TODO - create a test case for enrolment of a new disk with a new volume header
    // TODO - create a test case for enrolment of a disk with an existing passphrase keyslot
    // TODO - create a test case for enrolment of a disk with an existing backup keyslot

    use std::path::{Path, PathBuf};

    use cryptsetup_rs::device::{CryptDevice, crypt_device_type};
    use env_logger;
    use expectest::prelude::*;

    use context::{HasDbLocation, MainContext, PeroxideDbReader};
    use context::tests::{TemporaryDirContext, KeyfileOutput};
    use model::{NewContainerParameters, DbType, DbEntryType, DbEntry, VolumeId};
    use operation::{EnrollOperation, PerformCryptOperation};

    #[allow(unused_variables)]
    #[test]
    fn test_enroll_new_device_with_keyfile() {
        env_logger::init().unwrap();
        CryptDevice::enable_debug(true);

        let temp_context = TemporaryDirContext::new(DbType::Backup);
        let main_context = MainContext::new(temp_context.db_location().clone());

        let device_file = temp_context.new_device_file().unwrap();

        let container_params = Some(NewContainerParameters {
            cipher: "serpent-xts-plain".to_string(),
            hash: "sha256".to_string(),
            key_bits: 512,
        });
        let paths = vec![device_file.path().to_str().unwrap().to_string()];
        let keyfile_content = vec![0xB, 0xA, 0xA, 0xA];
        let (keyfile_path, keyfile_temp_file) = temp_context.write_keyfile(Some(Path::new("enroll_subdir")), &keyfile_content).unwrap();

        let enroll_op = EnrollOperation::<MainContext, MainContext> {
            context: main_context,
            entry_type: DbEntryType::Keyfile,
            new_container: container_params,
            device_paths_or_uuids: paths,
            iteration_ms: 10,
            keyfile: Some(keyfile_path.to_path_buf()),
            backup_context: None,
            name: Some("a_name".to_string()),
            yubikey_entry_type: None,
            yubikey_slot: None,
        };
        enroll_op.apply().unwrap();

        // verify the db got written correctly
        let crypt_device = CryptDevice::new(device_file.path().to_path_buf()).unwrap();
        expect!(crypt_device.load(crypt_device_type::LUKS1)).to(be_ok());
        expect!(crypt_device.uuid()).to(be_some());

        let db = temp_context.open_peroxide_db().unwrap();
        expect!(db.entries.iter()).to(have_count(1));

        let expected_entry = DbEntry::KeyfileEntry {
            key_file: PathBuf::from("enroll_subdir").join(keyfile_path.file_name().and_then(|n| n.to_str()).unwrap()),
            volume_id: VolumeId::new(Some("a_name".to_string()), crypt_device.uuid().unwrap()),
        };

        expect!(db.entries.first()).to(be_some().value(&expected_entry));

        // verify crypt device got setup correctly
        expect!(crypt_device.cipher()).to(be_some().value("serpent"));
        expect!(crypt_device.cipher_mode()).to(be_some().value("xts-plain"));
        expect!(crypt_device.volume_key_size()).to(be_some().value(64));

        // TODO - try to verify the keyslot parameters but there's no api it seems
    }


}
