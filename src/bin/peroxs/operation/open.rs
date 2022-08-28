use peroxide_cryptsetup::context::{Context, DatabaseOps, DeviceOps, PeroxideDbOps};
use std::str::FromStr;

use crate::operation::{Disks, OperationError as Error, PathOrUuid, Result};
use crate::DiskReference;
use vec1::Vec1;

#[derive(Debug)]
pub struct Params {
    /// List of device paths or UUIDs corresponding to the devices we want to open
    pub disk_references: Vec<DiskReference>,
    /// Name override (if a single device is present)
    pub name: Option<String>,
}

pub fn open<C: Context + DeviceOps>(ctx: &C, params: Params) -> Result<()> {
    let db = ctx.open_db()?;

    // TODO: check for existing mapping

    let paths = params
        .disk_references
        .into_iter()
        .map(|disk_ref| {
            db.find_entry_by_name(&disk_ref.0)
                .map(|e| Ok(PathOrUuid::Uuid(e.volume_id().uuid().to_owned())))
                .unwrap_or_else(|| PathOrUuid::from_str(&disk_ref.0))
                .and_then(|path_or| match path_or {
                    PathOrUuid::Uuid(uuid) => Ok(Disks::disk_uuid_path(&uuid)?),
                    PathOrUuid::Path(path) => Ok(path),
                })
        })
        .collect::<Result<Vec<_>>>()?;

    if paths.len() == 0 {
        return Err(Error::ValidationFailed(format!("Cannot open 0 devices")));
    } else {
        let path_vec1 = Vec1::try_from_vec(paths).expect("non-empty vec");
        let _ = ctx.open_disks(&db, path_vec1, params.name)?;
        Ok(())
    }
}
