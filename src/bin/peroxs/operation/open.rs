use peroxide_cryptsetup::context::{Context, DeviceOps, PeroxideDbOps};

use crate::operation::{Disks, OperationError as Error, PathOrUuid, Result};
use vec1::Vec1;

#[derive(Debug)]
pub struct Params {
    /// List of device paths or UUIDs corresponding to the devices we want to open
    pub device_paths_or_uuids: Vec<PathOrUuid>,
    /// Name override (if a single device is present)
    pub name: Option<String>,
}

pub fn open<C: Context + DeviceOps>(ctx: &C, params: Params) -> Result<()> {
    let db = ctx.open_db()?;

    let paths = params
        .device_paths_or_uuids
        .into_iter()
        .map(|path_or| match path_or {
            PathOrUuid::Uuid(uuid) => Ok(Disks::disk_uuid_path(&uuid)?),
            PathOrUuid::Path(path) => Ok(path),
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
