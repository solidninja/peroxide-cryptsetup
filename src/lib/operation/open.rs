use std::path::PathBuf;

use cryptsetup_rs;
use cryptsetup_rs::{Keyslot, Luks1CryptDevice};

use uuid::Uuid;

use context;
use io::Disks;
use model::{DbEntry, PeroxideDb, VolumeId};
use operation::{LuksDevice, OpenOperation, OperationError, PerformCryptOperation, Result, UserDiskLookup};

struct NamingContext {
    device_index: usize,
    is_single_device: bool,
}

impl NamingContext {
    fn device_name(&self, given_name: Option<&String>, volume_id: &VolumeId) -> String {
        given_name
            .or(volume_id.name.as_ref())
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
where
    Context: context::ReaderContext + context::InputContext,
{
    fn apply(&self) -> Result<()> {
        let db = self.context
            .open_peroxide_db()
            .map_err(|_| OperationError::DbOpenFailed)?;
        let _db = &db; // NLL is dead, long live NLL ¯＼(º_o)/¯
        let device_paths = self.lookup_device_paths()?;

        let devices_with_entries = device_paths
            .into_iter()
            .enumerate()
            .map(|(idx, path)| {
                let device = cryptsetup_rs::open(&path)
                    .and_then(|open| open.luks1())
                    .map_err(|err| (&path, err))?;

                let entry = self.find_entry(_db, &device.uuid())?;

                let name_ctx = NamingContext {
                    is_single_device: self.device_paths_or_uuids.len() == 1,
                    device_index: idx,
                };

                let _ = self.validate_open_entry(entry, &name_ctx)?;

                Ok((device, entry, name_ctx))
            })
            .collect::<Result<Vec<_>>>()?;

        devices_with_entries
            .into_iter()
            .map(|(ref mut device, ref entry, ref name_ctx)| self.open_entry(device, entry, name_ctx))
            .collect::<Result<Vec<_>>>()
            .map(|_| ()) // TODO better pattern?
    }
}

impl<Context> OpenOperation<Context>
where
    Context: context::ReaderContext + context::InputContext,
{
    fn lookup_device_paths(&self) -> Result<Vec<PathBuf>> {
        // TODO - same comment in register.rs - better way to convert Vec<String> -> &[&str]
        let device_paths_or_uuids: Vec<&str> = self.device_paths_or_uuids.iter().map(|s| s.as_ref()).collect();
        // killed by the ::<>
        let mut device_map = self.context.resolve_paths_or_uuids(&device_paths_or_uuids);
        let res = device_map.drain().map(|kv| kv.1).collect::<context::Result<Vec<_>>>()?;
        Ok(res)
    }

    fn find_entry<'a>(&self, db: &'a PeroxideDb, uuid: &Uuid) -> Result<&'a DbEntry> {
        db.entries
            .iter()
            .find(|e| e.uuid() == uuid)
            .ok_or_else(|| OperationError::NotFoundInDb(format!("Uuid {} not found in db", uuid)))
    }

    fn validate_open_entry<'a>(&self, db_entry: &'a DbEntry, name_ctx: &NamingContext) -> Result<&'a DbEntry> {
        let proposed_name = name_ctx.device_name(self.name.as_ref(), db_entry.volume_id());
        if Disks::is_device_mapped(&proposed_name) {
            Err(OperationError::ValidationFailed(format!(
                "Device '{}' is already mapped!",
                proposed_name
            )))
        } else {
            Ok(db_entry)
        }
    }

    fn open_entry(&self, device: &mut LuksDevice, db_entry: &DbEntry, name_ctx: &NamingContext) -> Result<Keyslot> {
        let name = name_ctx.device_name(self.name.as_ref(), db_entry.volume_id());
        match db_entry {
            &DbEntry::KeyfileEntry { .. } => self.open_keyfile(device, db_entry, &name),
            &DbEntry::PassphraseEntry { .. } => self.open_passphrase(device, db_entry, &name),
            &DbEntry::YubikeyEntry { .. } => self.open_yubikey(device, db_entry, &name),
        }
    }

    fn open_keyfile(&self, cd: &mut LuksDevice, db_entry: &DbEntry, name: &str) -> Result<Keyslot> {
        if let &DbEntry::KeyfileEntry { ref key_file, .. } = db_entry {
            self.context.read_keyfile(key_file).map_err(From::from).and_then(|key| {
                cd.activate(&name, key.as_slice())
                    .map_err(|e| From::from((cd.path(), e)))
            })
        } else {
            Err(OperationError::BugExplanation(format!(
                "Expected KeyfileEntry, but got {:?}",
                db_entry
            )))
        }
    }

    fn open_passphrase(&self, cd: &mut LuksDevice, db_entry: &DbEntry, name: &str) -> Result<Keyslot> {
        if let &DbEntry::PassphraseEntry { .. } = db_entry {
            let prompt = format!("Please enter passphrase to open '{}':", name);
            self.context.read_password(&prompt).map_err(From::from).and_then(|key| {
                cd.activate(&name, key.as_slice())
                    .map_err(|e| From::from((cd.path(), e)))
            })
        } else {
            Err(OperationError::BugExplanation(format!(
                "Expected PassphraseEntry, but got {:?}",
                db_entry
            )))
        }
    }

    fn open_yubikey(&self, cd: &mut LuksDevice, db_entry: &DbEntry, name: &str) -> Result<Keyslot> {
        if let &DbEntry::YubikeyEntry {
            ref slot,
            ref entry_type,
            ref volume_id,
        } = db_entry
        {
            self.context
                .read_yubikey(Some(name), &volume_id.id.uuid, slot.clone(), entry_type.clone())
                .map_err(From::from)
                .and_then(|key| {
                    cd.activate(&name, key.as_slice())
                        .map_err(|e| From::from((cd.path(), e)))
                })
        } else {
            Err(OperationError::BugExplanation(format!(
                "Expected YubikeyEntry, but got {:?}",
                db_entry
            )))
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
        let expected_name = format!("uuid_{}", uuid.hyphenated().to_string());

        let single_context = NamingContext {
            is_single_device: true,
            device_index: 42,
        };
        let multi_context = NamingContext {
            is_single_device: false,
            ..single_context
        };

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
        let multi_context = NamingContext {
            is_single_device: false,
            ..single_context
        };

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
        let multi_context = NamingContext {
            is_single_device: false,
            ..single_context
        };

        expect!(single_context.device_name(None, &volume_id)).to(be_equal_to("foo"));
        expect!(single_context.device_name(foobar.as_ref(), &volume_id)).to(be_equal_to("foobar"));

        expect!(multi_context.device_name(None, &volume_id)).to(be_equal_to("foo_21"));
        expect!(multi_context.device_name(foobar.as_ref(), &volume_id)).to(be_equal_to("foobar_21"));
    }
}
