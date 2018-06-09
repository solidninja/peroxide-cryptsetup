use uuid;

use peroxide_cryptsetup::context;
use peroxide_cryptsetup::context::{KeyWrapper, YubikeyInput};
use peroxide_cryptsetup::model::{YubikeyEntryType, YubikeySlot};

use support::*;

impl YubikeyInput for TemporaryDirContext {
    #[allow(unused)]
    fn read_yubikey(
        &self,
        name: Option<&str>,
        uuid: &uuid::Uuid,
        slot: YubikeySlot,
        entry_type: YubikeyEntryType,
    ) -> context::Result<KeyWrapper> {
        unimplemented!()
    }
}
