use peroxide_cryptsetup::context::{Context, PeroxideDbOps};
use peroxide_cryptsetup::db::{DbType, PeroxideDb};

use crate::operation::{OperationError, Result};

/// Parameters to the `newdb` command (namely just a database type)
pub struct Params(pub DbType);

/// Create a new database at the location given by the context
pub fn newdb<C: Context>(ctx: &C, params: Params) -> Result<()> {
    if ctx.db_location().exists() {
        Err(OperationError::ValidationFailed(format!(
            "Database already exists at {}",
            ctx.db_location().display()
        )))
    } else {
        ctx.save_db(&PeroxideDb::new(params.0))?;
        Ok(())
    }
}
