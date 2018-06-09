pub use db::{DbEntry, DbEntryType, DbType, PeroxideDb, VolumeId, VolumeUuid, YubikeyEntryType, YubikeySlot};
pub use operation::{
    CryptOperation, EnrollOperation, ListOperation, NewContainerParameters, NewDatabaseOperation, OpenOperation,
    OperationError, RegisterOperation,
};

use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct DbLocation {
    pub path: PathBuf,
    pub db_type: DbType,
}
