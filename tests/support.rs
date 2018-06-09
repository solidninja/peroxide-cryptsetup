use std::fs;
use std::io;
use std::io::{Seek, Write};
use std::path::{Path, PathBuf};

use tempdir::TempDir;
use tempfile::NamedTempFile;
use uuid;

use cryptsetup_rs;
use peroxide_cryptsetup::context;
use peroxide_cryptsetup::context::{
    DiskSelector, HasDbLocation, InputContext, KeyWrapper, KeyfileInput, MainContext, PasswordInput, PeroxideDbReader,
    PeroxideDbWriter, ReaderContext, WriterContext,
};
use peroxide_cryptsetup::model::{DbLocation, DbType, PeroxideDb};

#[cfg(not(feature = "yubikey"))]
use peroxide_cryptsetup::context::YubikeyInput;

#[cfg(not(feature = "yubikey"))]
use peroxide_cryptsetup::model::{YubikeyEntryType, YubikeySlot};

pub fn setup() {
    cryptsetup_rs::enable_debug(true);
}

#[allow(dead_code)]
pub struct TemporaryDirContext {
    main_context: MainContext,
    temp_dir: TempDir,
    db: PeroxideDb,
}

impl TemporaryDirContext {
    pub fn new(db_type: DbType) -> TemporaryDirContext {
        let db = PeroxideDb::new(db_type);
        let temp_dir = TempDir::new("db_test").unwrap();
        let db_location = DbLocation {
            path: temp_dir.path().join("temp.db"),
            db_type,
        };
        let main_context = MainContext::new(db_location);
        main_context.save_peroxide_db(&db).unwrap();
        TemporaryDirContext {
            main_context,
            temp_dir,
            db,
        }
    }

    pub fn new_device_file(&self) -> io::Result<NamedTempFile> {
        let temp_file = NamedTempFile::new_in(self.temp_dir.path())?;
        temp_file.as_file().set_len(150000000)?; // 15 mb
        Ok(temp_file)
    }

    pub fn write_keyfile(&self, maybe_subdir: Option<&Path>, contents: &[u8]) -> io::Result<NamedTempFile> {
        let in_path = maybe_subdir.map_or_else(
            || self.temp_dir.path().to_path_buf(),
            |subdir| self.temp_dir.path().join(subdir),
        );
        fs::create_dir_all(&in_path)?;
        NamedTempFile::new_in(in_path).and_then(|mut temp_file| {
            temp_file.seek(io::SeekFrom::Start(0))?;
            temp_file.write_all(contents)?;
            temp_file.seek(io::SeekFrom::Start(0))?;
            Ok(temp_file)
        })
    }
}

impl HasDbLocation for TemporaryDirContext {
    fn db_location<'a>(&'a self) -> &'a DbLocation {
        self.main_context.db_location()
    }
}

impl PeroxideDbReader for TemporaryDirContext {
    fn open_peroxide_db(&self) -> context::Result<PeroxideDb> {
        self.main_context.open_peroxide_db()
    }
}

impl PeroxideDbWriter for TemporaryDirContext {
    fn save_peroxide_db(&self, db: &PeroxideDb) -> context::Result<()> {
        self.main_context.save_peroxide_db(db)
    }
}

impl KeyfileInput for TemporaryDirContext {
    fn read_keyfile(&self, path: &Path) -> context::Result<KeyWrapper> {
        self.main_context.read_keyfile(path)
    }
}

impl PasswordInput for TemporaryDirContext {
    #[allow(unused)]
    fn read_password(&self, prompt: &str) -> context::Result<KeyWrapper> {
        unimplemented!()
    }
}

#[cfg(not(feature = "yubikey"))]
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

impl DiskSelector for TemporaryDirContext {
    #[allow(unused)]
    fn all_disk_uuids(&self) -> context::Result<Vec<uuid::Uuid>> {
        unimplemented!()
    }

    #[allow(unused)]
    fn disk_uuid_path(&self, uuid: &uuid::Uuid) -> context::Result<PathBuf> {
        unimplemented!()
    }
}

impl ReaderContext for TemporaryDirContext {}
impl WriterContext for TemporaryDirContext {}
impl InputContext for TemporaryDirContext {}

pub trait RelativeTo {
    fn relative_to(&self, context: &TemporaryDirContext) -> PathBuf;
}

impl RelativeTo for NamedTempFile {
    fn relative_to(&self, context: &TemporaryDirContext) -> PathBuf {
        // FIXME suboptimal impl, Rust 1.5 needed
        if !self.path().starts_with(context.temp_dir.path()) {
            self.path().to_path_buf()
        } else {
            let base_path = format!("{}/", context.temp_dir.path().display());
            let file_path = format!("{}", self.path().display());
            PathBuf::from(file_path.trim_left_matches(&base_path))
        }
    }
}
