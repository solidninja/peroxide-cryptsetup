use operation::{PerformCryptOperation, NewDatabaseOperation, Result, OperationError};
use model::PeroxideDb;
use context;
use io::FileExtensions;

impl<Context: context::WriterContext> PerformCryptOperation for NewDatabaseOperation<Context> {
    fn apply(&self) -> Result<()> {
        if !self.context.db_location().exists() {
            let the_db = PeroxideDb::new(self.context.db_location().db_type.clone());
            try!(self.context.save_peroxide_db(&the_db));
            Ok(())
        } else {
            Err(OperationError::ValidationFailed("File already exists at this location".to_string()))
        }
    }
}
