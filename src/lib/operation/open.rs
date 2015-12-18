use cryptsetup_rs::device::{crypt_device_type, CryptDevice};


use context::{DiskSelector, KeyfileInput, PeroxideDbReader};
use context;
use io::Disks;
use model::{DbEntry, VolumeId};
use operation::{PerformCryptOperation, OpenOperation, OperationError, UserDiskLookup, Result};

struct NamingContext {
    device_index: usize,
    is_single_device: bool,
}

impl NamingContext {
    fn device_name(&self, given_name: Option<&String>, volume_id: &VolumeId) -> String {
        given_name.or(volume_id.name.as_ref())
                  .map(|name| {
                      if !self.is_single_device {
                          format!("{}_{}", name, self.device_index)
                      } else {
                          name.clone()
                      }
                  })
                  .unwrap_or_else(|| format!("uuid_{}", volume_id.id.uuid))
    }
}

impl<Context> PerformCryptOperation for OpenOperation<Context>
    where Context: context::ReaderContext + context::InputContext + context::DiskSelector
{
    fn apply(self) -> Result<()> {
        let db = try!(self.context.open_peroxide_db().map_err(|_| OperationError::DbOpenFailed));

        // TODO - do we need to incorporate blkid_rs::BlockDevice::read_luks_header or is device.load() enough?
        let devices = try!(self.context.lookup_devices(&self.device_paths_or_uuids));

        let mut devices_with_entries = try!(devices.into_iter()
                                                   .enumerate()
                                                   .map(|(idx, device)| {
                                                       if let Err(err) = device.load(crypt_device_type::LUKS1) {
                                                           Err(From::from((device.path.clone(), err)))
                                                       } else {
                                                           let single_device = self.device_paths_or_uuids.len() == 1;
                                                           let name_ctx = NamingContext {
                                                               is_single_device: single_device,
                                                               device_index: idx,
                                                           };
                                                           let uuid = device.uuid().unwrap();
                                                           let maybe_entry =
                                                               db.entries
                                                                 .iter()
                                                                 .find(|e| e.uuid() == &uuid)
                                                                 .ok_or_else(|| {
                                                                     OperationError::NotFoundInDb(format!("Uuid {} not found in db", uuid))
                                                                 });

                                                           maybe_entry.and_then(|entry| self.validate_open_entry(entry, &name_ctx))
                                                                      .map(|entry| (device, entry, name_ctx))
                                                       }
                                                   })
                                                   .collect::<Result<Vec<_>>>());

        devices_with_entries.iter_mut()
                            .map(|&mut (ref mut device, ref entry, ref name_ctx)| self.open_entry(device, entry, name_ctx))
                            .collect::<Result<Vec<()>>>()
                            .map(|_| ())  // TODO better pattern?
    }
}

impl<Context> OpenOperation<Context> where Context: context::ReaderContext + context::InputContext + context::DiskSelector
{
    fn validate_open_entry<'a>(&self, db_entry: &'a DbEntry, name_ctx: &NamingContext) -> Result<&'a DbEntry> {
        let proposed_name = name_ctx.device_name(self.name.as_ref(), db_entry.volume_id());
        if Disks::is_device_mapped(&proposed_name) {
            Err(OperationError::ValidationFailed(format!("Device '{}' is already mapped!", proposed_name)))
        } else {
            Ok(db_entry)
        }
    }

    fn open_entry(&self, device: &mut CryptDevice, db_entry: &DbEntry, name_ctx: &NamingContext) -> Result<()> {
        let name = name_ctx.device_name(self.name.as_ref(), db_entry.volume_id());
        match db_entry {
            &DbEntry::KeyfileEntry { .. } => self.open_keyfile(device, db_entry, &name),
            &DbEntry::PassphraseEntry { .. } => self.open_passphrase(device, db_entry, &name),
            &DbEntry::YubikeyEntry { .. } => self.open_yubikey(device, db_entry, &name),
        }
    }

    fn open_keyfile(&self, cd: &mut CryptDevice, db_entry: &DbEntry, name: &str) -> Result<()> {
        if let &DbEntry::KeyfileEntry { ref key_file, .. } = db_entry {
            self.context
                .read_keyfile(key_file)
                .map_err(From::from)
                .and_then(|key| cd.activate(&name, key.as_slice()).map_err(|e| From::from((cd.path.clone(), e))))
        } else {
            Err(OperationError::BugExplanation(format!("Expected KeyfileEntry, but got {:?}", db_entry)))
        }
    }

    fn open_passphrase(&self, cd: &mut CryptDevice, db_entry: &DbEntry, name: &str) -> Result<()> {
        if let &DbEntry::PassphraseEntry { .. } = db_entry {
            let prompt = format!("Please enter passphrase to open '{}':", name);
            self.context
                .read_password(&prompt)
                .map_err(From::from)
                .and_then(|key| cd.activate(&name, key.as_slice()).map_err(|e| From::from((cd.path.clone(), e))))
        } else {
            Err(OperationError::BugExplanation(format!("Expected PassphraseEntry, but got {:?}", db_entry)))
        }
    }

    fn open_yubikey(&self, cd: &mut CryptDevice, db_entry: &DbEntry, name: &str) -> Result<()> {
        if let &DbEntry::YubikeyEntry { ref slot, ref entry_type, ref volume_id } = db_entry {
            self.context
                .read_yubikey(Some(name),
                              &volume_id.id.uuid,
                              slot.clone(),
                              entry_type.clone())
                .map_err(From::from)
                .and_then(|key| cd.activate(&name, key.as_slice()).map_err(|e| From::from((cd.path.clone(), e))))
        } else {
            Err(OperationError::BugExplanation(format!("Expected YubikeyEntry, but got {:?}", db_entry)))
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::NamingContext;

    use expectest::prelude::*;
    use uuid::Uuid;

    use model::VolumeId;

    #[test]
    fn test_device_name_uuid_fallback() {
        let uuid = Uuid::new_v4();
        let volume_id = VolumeId::new(None, uuid);
        let expected_name = format!("uuid_{}", uuid.to_hyphenated_string());

        let single_context = NamingContext {
            is_single_device: true,
            device_index: 42,
        };
        let multi_context = NamingContext { is_single_device: false, ..single_context };

        expect!(single_context.device_name(None, &volume_id)).to(be_equal_to(expected_name.clone()));
        expect!(multi_context.device_name(None, &volume_id)).to(be_equal_to(expected_name.clone()));
    }

    #[test]
    fn test_device_name_given() {
        let volume_id = VolumeId::new(None, Uuid::new_v4());
        let foobar = Some("foobar".to_string());

        let single_context = NamingContext {
            is_single_device: true,
            device_index: 42,
        };
        let multi_context = NamingContext { is_single_device: false, ..single_context };

        expect!(single_context.device_name(foobar.as_ref(), &volume_id)).to(be_equal_to("foobar"));
        expect!(multi_context.device_name(foobar.as_ref(), &volume_id)).to(be_equal_to("foobar_42"));
    }

    #[test]
    fn test_device_name_from_volume_id() {
        let volume_id = VolumeId::new(Some("foo".to_string()), Uuid::new_v4());
        let foobar = Some("foobar".to_string());

        let single_context = NamingContext {
            is_single_device: true,
            device_index: 21,
        };
        let multi_context = NamingContext { is_single_device: false, ..single_context };

        expect!(single_context.device_name(None, &volume_id)).to(be_equal_to("foo"));
        expect!(single_context.device_name(foobar.as_ref(), &volume_id)).to(be_equal_to("foobar"));

        expect!(multi_context.device_name(None, &volume_id)).to(be_equal_to("foo_21"));
        expect!(multi_context.device_name(foobar.as_ref(), &volume_id)).to(be_equal_to("foobar_21"));
    }
}
