use snafu::ResultExt;

use peroxide_cryptsetup::context::{Context, PeroxideDbOps};
use peroxide_cryptsetup::db::{DbType, PeroxideDb};

use crate::operation::{ContextSnafu, Result, ValidationSnafu};

/// Parameters to the `newdb` command (namely just a database type)
pub struct Params(pub DbType);

/// Create a new database at the location given by the context
pub fn newdb<C: Context>(ctx: &C, params: Params) -> Result<()> {
    if ctx.db_location().exists() {
        Err(ValidationSnafu {
            message: format!("Database already exists at {}", ctx.db_location().display()),
        }
        .build())
    } else {
        ctx.save_db(&PeroxideDb::new(params.0)).context(ContextSnafu)?;
        Ok(())
    }
}
