use peroxide_cryptsetup::context::{Context, DatabaseOps, DeviceOps, PeroxideDbOps};
use peroxide_cryptsetup::db::VolumeId;

use crate::operation::{Disks, OperationError as Error, PathOrUuid, Result};
use peroxide_cryptsetup::device::LuksVolumeOps;

#[derive(Debug)]
pub struct Params {
    /// List of device paths or UUIDs corresponding to the devices we want to open
    pub device_paths_or_uuids: Vec<PathOrUuid>,
    /// Name override (if a single device is present)
    pub name: Option<String>,
}

pub fn open<C: Context + DeviceOps>(ctx: &C, params: Params) -> Result<()> {
    let db = ctx.open_db()?;

    let num_params = params.device_paths_or_uuids.len();
    let entries_with_path = params
        .device_paths_or_uuids
        .iter()
        .map(|path_or| match path_or {
            PathOrUuid::Uuid(uuid) => {
                let path = Disks::disk_uuid_path(&uuid)?;
                Ok((uuid.clone(), path))
            }
            PathOrUuid::Path(path) => {
                let uuid = path.luks_uuid()?;
                Ok((uuid, path.clone()))
            }
        })
        .map(|res| {
            res.and_then(|(uuid, path)| {
                if let Some(entry) = db.find_entry(&uuid) {
                    Ok((entry, path))
                } else {
                    Err(Error::NotFoundInDb(format!(
                        "No DB entry for UUID: {}, path: {:?}",
                        uuid, path
                    )))
                }
            })
        })
        .collect::<Result<Vec<_>>>()?;

    // check dups
    {
        let mut volume_ids: Vec<VolumeId> = entries_with_path.iter().map(|ep| ep.0.volume_id().clone()).collect();
        volume_ids.sort();
        volume_ids.dedup();
        if num_params > volume_ids.len() {
            return Err(Error::ValidationFailed(format!(
                "Duplicates found in disks specified, please specify a disk only once"
            )));
        }
    }

    match entries_with_path.len() {
        0 => Err(Error::ValidationFailed(format!("Cannot open 0 devices"))),
        // single entry, only open one device
        1 => {
            let (entry, path) = entries_with_path.first().expect("first entry");
            // always override path, it may be a normal file instead of a block device that udev knows about
            let _ = ctx.activate(&entry, params.name, Some(path))?;
            Ok(())
        }
        // multiple entries, pick first entry for key prompt and then open devices one by one
        _ => {
            let (first, _) = entries_with_path.first().expect("first entry");
            let key = ctx.prompt_key(
                first,
                Some(format!(
                    "Please enter key for multiple disks [{}, ...]",
                    first.volume_id()
                )),
                false,
            )?;
            let _ = entries_with_path
                .iter()
                .enumerate()
                .map(|idx_entry| {
                    let (idx, (entry, path)) = idx_entry;
                    // if override name is provided, all disks will start with the same prefix and will be identified by index
                    let name = params.name.as_ref().map(|name| format!("{}_{}", name, idx));
                    let _ = ctx.activate_with_key(&entry, &key, name, Some(path))?;
                    Ok(())
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(())
        }
    }
}

// TODO - write test for naming (and for opening of course!)
