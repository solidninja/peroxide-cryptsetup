pub use db::{PeroxideDb, DbType, DbEntryType, DbEntry, VolumeId, VolumeUuid, YubikeySlot, YubikeyEntryType};
pub use operation::{NewContainerParameters, CryptOperation, OpenOperation, NewDatabaseOperation, EnrollOperation, ListOperation, OperationError};

use std::path::PathBuf;


#[derive(Debug, Clone)]
pub struct DbLocation {
    pub path: PathBuf,
    pub db_type: DbType,
}
