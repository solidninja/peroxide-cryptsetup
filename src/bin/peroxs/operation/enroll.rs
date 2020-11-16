use peroxide_cryptsetup::context::{Context, DeviceOps, DiskEnrolmentParams, PeroxideDbOps};
use std::convert::TryFrom;
use vec1::Vec1;

use crate::operation::{OperationError as Error, PathOrUuid, Result};
use peroxide_cryptsetup::input::BackupPrompt;

#[derive(Debug)]
pub struct Params<BCtx: Context + DeviceOps> {
    /// List of device paths or UUIDs corresponding to the devices we want to enroll
    pub device_paths_or_uuids: Vec<PathOrUuid>,
    /// Backup context (if using a backup database)
    pub backup_context: Option<BCtx>,
    /// Disk enrollment parameters
    pub params: DiskEnrolmentParams,
}

pub fn enroll<Ctx: Context + DeviceOps, BCtx: Context + DeviceOps>(ctx: &Ctx, params: Params<BCtx>) -> Result<()> {
    let mut db = ctx.open_db()?;

    let paths = params
        .device_paths_or_uuids
        .iter()
        .map(|p| p.to_path())
        .collect::<Result<Vec<_>>>()?;
    let paths_v1 = if let Some(vec) = Vec1::try_from(paths).ok() {
        vec
    } else {
        return Err(Error::ValidationFailed(format!(
            "At least one path/uuid must be supplied"
        )));
    };

    let backup_db = if let Some(bctx) = params.backup_context {
        let bdb = bctx.open_db()?;
        Some(BackupPrompt { db: bdb, ctx: bctx })
    } else {
        None
    };

    ctx.enroll_disks(&mut db, paths_v1, params.params, backup_db)?;

    Ok(())
}
