#![deny(warnings)]
#[warn(unused_must_use)]

extern crate docopt;
extern crate peroxide_cryptsetup;

#[macro_use]
extern crate serde_derive;

// TODO - improve the logging story?
extern crate env_logger;

use std::path::{Path, PathBuf};
use std::env;
use std::fmt;
use std::io;
use std::fs;
use std::process::exit;
use std::result;

use docopt::Docopt;

use peroxide_cryptsetup::model::{OpenOperation, EnrollOperation, NewDatabaseOperation, ListOperation,
                                 CryptOperation, PeroxideDb, DbLocation, DbEntryType, DbType,
                                 NewContainerParameters, YubikeyEntryType, RegisterOperation};
use peroxide_cryptsetup::context::MainContext;

type Result<T> = result::Result<T, CmdError>;

enum CmdError {
    DatabaseNotAvailable(io::Error),
    UnrecognisedOperation,
}

impl fmt::Display for CmdError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &CmdError::UnrecognisedOperation => write!(fmt, "Operation was not recognised. This is probably a bug."),
            &CmdError::DatabaseNotAvailable(ref err) => write!(fmt, "No peroxs database file '{}' found: {}", PEROXIDE_DB_NAME, err),
        }
    }
}

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

static USAGE: &'static str = "
Usage:
    peroxs enroll keyfile <keyfile> <device-or-uuid>... --iteration-ms=<iteration-ms> [--backup-db=<backup-db>] [--name=<name>] [at <db>]
    peroxs enroll keyfile <keyfile> new --cipher=<cipher> --hash=<hash> --key-bits=<key-bits> <device-or-uuid>... --iteration-ms=<iteration-ms> [--backup-db=<backup-db>] [--name=<name>] [at <db>]
    peroxs enroll passphrase <device-or-uuid>... --iteration-ms=<iteration-ms> [--backup-db=<backup-db>] [--name=<name>] [at <db>]
    peroxs enroll passphrase new --cipher=<cipher> --hash=<hash> --key-bits=<key-bits> <device-or-uuid>... --iteration-ms=<iteration-ms> [--backup-db=<backup-db>] [--name=<name>] [at <db>]
    peroxs enroll yubikey [hybrid] --slot=<slot> <device-or-uuid>... --iteration-ms=<iteration-ms> [--backup-db=<backup-db>] [--name=<name>] [at <db>]
    peroxs enroll yubikey [hybrid] --slot=<slot> new --cipher=<cipher> --hash=<hash> --key-bits=<key-bits> <device-or-uuid>... --iteration-ms=<iteration-ms> [--backup-db=<backup-db>] [--name=<name>] [at <db>]
    peroxs init <db-type> [at <db>]
    peroxs list [--all]
    peroxs open <device-or-uuid>... [--name=<name>] [at <db>]
    peroxs register keyfile <keyfile> <device-or-uuid>...  [--name=<name>] [at <db>]
    peroxs register passphrase <device-or-uuid>...  [--name=<name>] [at <db>]
    peroxs (--help | --version)

Actions:
    enroll                                  Enroll a new or existing LUKS disk(s) with a given key type and parameters 
    init                                    Create a new database of the specified type
    list                                    List disks that are in the database and available
    open                                    Open an existing LUKS disk(s) with parameters from the database
    register                                Add an existing keyfile/passphrase entry in the database for a LUKS disk(s)

Enrollment types:
    keyfile                                 An existing key file with randomness inside
    passphrase                              A password or passphrase
    yubikey                                 A Yubikey (combined with challenge)
    yubikey hybrid                          A Yubikey (combined with challenge) and a secondary passphrase

Arguments:
    <db>                                    The path to the database
    <db-type>                               The database type (used when creating). One of: operation,backup
    <device-or-uuid>                        The path to the device or the uuid of the device
    <keyfile>                               The path to the key file 

Options:
    --help                                  Show this message
    --version                               Show the version of peroxs and libraries.

    --backup-db <backup-db>                 The path to the backup database to use (if any)
    -c <cipher>, --cipher <cipher>          Cipher to use for new LUKS container
    -i <ms>, --iteration-ms <ms>            Number of milliseconds to wait for the PBKDF2 function iterations
    -h <hash>, --hash <hash>                Hash function to use for new LUKS container
    -n <name>, --name <name>                Name for the device being enrolled
    -s <key-bits>, --key-bits <key-bits>    Number of key bits to use for new LUKS container
    -S <slot>, --slot <slot>                Slot in Yubikey to use
";

#[derive(Deserialize, Debug)]
struct Args {
    cmd_init: bool,
    cmd_enroll: bool,
    cmd_new: bool,
    cmd_open: bool,
    cmd_keyfile: bool,
    cmd_list: bool,
    cmd_passphrase: bool,
    cmd_yubikey: bool,
    cmd_hybrid: bool,
    cmd_at: bool,
    cmd_register: bool,
    arg_db: Option<String>,
    arg_db_type: Option<String>,
    arg_device_or_uuid: Option<Vec<String>>,
    arg_keyfile: Option<String>,
    flag_version: bool,
    flag_all: bool,
    flag_help: bool,
    flag_cipher: Option<String>,
    flag_hash: Option<String>,
    flag_key_bits: Option<usize>,
    flag_backup_db: Option<String>,
    flag_iteration_ms: Option<usize>,
    flag_name: Option<String>,
    flag_slot: Option<u8>,
}

const PEROXIDE_DB_NAME: &'static str = "peroxs-db.json";

fn _guess_db_path() -> io::Result<PathBuf> {
    env::current_dir().map(|dir| dir.join(PEROXIDE_DB_NAME))
}

fn get_db_path(arg_db: Option<PathBuf>) -> io::Result<PathBuf> {
    arg_db.map(|p| Ok(p.clone()))
        .unwrap_or_else(_guess_db_path)
}

fn get_db_type<P: AsRef<Path>>(db_path: &P) -> io::Result<DbType> {
    fs::File::open(db_path)
        .and_then(PeroxideDb::from)
        .map(|db| db.db_type.clone())
}

fn get_db_location(at_path: Option<PathBuf>, maybe_db_type: Option<&DbType>) -> io::Result<DbLocation> {
    let db_path = get_db_path(at_path)?;
    let db_type = maybe_db_type.map(|t| Ok(t.clone()))
        .unwrap_or_else(|| get_db_type(&db_path))?;
    Ok(DbLocation {
        path: db_path,
        db_type: db_type,
    })
}

fn get_backup_db_location(at_path: Option<PathBuf>) -> Option<DbLocation> {
    get_db_location(at_path, None).ok()
}

fn get_new_container_parameters(args: &Args) -> Option<NewContainerParameters> {
    if args.cmd_new {
        let cipher = args.flag_cipher.as_ref().map_or_else(|| panic!("Must supply a cipher string"), |s| s.clone());
        let hash = args.flag_hash.as_ref().map_or_else(|| panic!("Must supply a hash"), |s| s.clone());
        let key_bits = args.flag_key_bits.unwrap_or_else(|| panic!("Must supply key bits"));
        Some(NewContainerParameters {
            cipher: cipher,
            hash: hash,
            key_bits: key_bits,
        })
    } else {
        None
    }
}

fn get_yubikey_entry_type(args: &Args) -> Option<YubikeyEntryType> {
    if args.cmd_yubikey {
        let entry_type = if args.cmd_hybrid {
            YubikeyEntryType::HybridChallengeResponse
        } else {
            YubikeyEntryType::ChallengeResponse
        };
        if args.flag_slot.is_none() {
            panic!("expecting slot to be specified")
        }
        Some(entry_type)
    } else {
        None
    }
}

fn get_entry_type(args: &Args) -> DbEntryType {
    match args {
        _ if args.cmd_passphrase => DbEntryType::Passphrase,
        _ if args.cmd_keyfile => DbEntryType::Keyfile,
        _ if args.cmd_yubikey => DbEntryType::Yubikey,
        _ => panic!("BUG: Unrecognised entry type!"),
    }
}

fn _enroll_operation(args: &Args, context: MainContext, maybe_paths: Option<Vec<String>>) -> CryptOperation {
    let backup_db_context = get_backup_db_location(args.flag_backup_db.as_ref().map(PathBuf::from)).map(MainContext::new);
    let new_container = get_new_container_parameters(args);
    let iteration_ms = args.flag_iteration_ms.unwrap_or_else(|| panic!("expecting iteration ms"));
    let device_paths_or_uuids = maybe_paths.unwrap_or_else(|| panic!("expecting device paths or uuids"));
    let entry_type = get_entry_type(&args);
    let name = args.flag_name.clone();
    let maybe_keyfile = args.arg_keyfile.as_ref().map(PathBuf::from);
    let yubikey_entry_type = get_yubikey_entry_type(args);
    CryptOperation::Enroll(EnrollOperation {
        context: context,
        entry_type: entry_type,
        new_container: new_container,
        device_paths_or_uuids: device_paths_or_uuids,
        iteration_ms: iteration_ms,
        keyfile: maybe_keyfile,
        backup_context: backup_db_context,
        name: name,
        yubikey_slot: args.flag_slot.clone(),
        yubikey_entry_type: yubikey_entry_type,
    })
}

fn _open_operation(args: &Args, context: MainContext, maybe_paths: Option<Vec<String>>) -> CryptOperation {
    let device_paths_or_uuids = maybe_paths.expect("expecting device paths or uuids");
    let name = args.flag_name.clone();

    CryptOperation::Open(OpenOperation {
        context: context,
        device_paths_or_uuids: device_paths_or_uuids,
        name: name,
    })
}

fn _register_operation(args: &Args, context: MainContext, maybe_paths: Option<Vec<String>>) -> CryptOperation {
    let device_paths_or_uuids = maybe_paths.expect("expecting device paths or uuids");
    let name = args.flag_name.clone();
    let maybe_keyfile = args.arg_keyfile.as_ref().map(PathBuf::from);
    let entry_type = get_entry_type(&args);

    CryptOperation::Register(RegisterOperation {
        context: context,
        device_paths_or_uuids: device_paths_or_uuids,
        name: name,
        keyfile: maybe_keyfile,
        entry_type: entry_type,
    })
}

fn get_operation(args: &Args) -> Result<CryptOperation> {
    let db_type = args.arg_db_type.as_ref().map(|s| match s.as_ref() {
        "operation" => DbType::Operation,
        "backup" => DbType::Backup,
        _ => panic!("Unknown db_type!")
    });
    let db_location = get_db_location(args.arg_db.as_ref().map(PathBuf::from),
                                      db_type.as_ref())
        .map_err(|err| CmdError::DatabaseNotAvailable(err))?;
    let context = MainContext::new(db_location);
    let maybe_paths = args.arg_device_or_uuid.clone();

    match args {
        _ if args.cmd_enroll => Ok(_enroll_operation(args, context, maybe_paths)),
        _ if args.cmd_init => Ok(CryptOperation::NewDatabase(NewDatabaseOperation { context: context })),
        _ if args.cmd_list => Ok(CryptOperation::List(ListOperation { context: context, only_available: !args.flag_all })),
        _ if args.cmd_open => Ok(_open_operation(args, context, maybe_paths)),
        _ if args.cmd_register => Ok(_register_operation(args, context, maybe_paths)),
        _ => Err(CmdError::UnrecognisedOperation)
    }
}

fn run_peroxs() -> i32 {
    env_logger::init().unwrap();
    // this enables verbose logging in the cryptsetup lib
    // TODO: remove this or move to feature flag
    MainContext::trace_on();

    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.argv(env::args().into_iter()).deserialize())
        .unwrap_or_else(|e| e.exit());

    let operation = get_operation(&args);

    if args.flag_version {
        println!("peroxs {}", VERSION);
        0
    } else if let Ok(op) = operation {
        if let Err(error) = op.perform() {
            println!("ERROR: {}", error);
            -1
        } else {
            0
        }
    } else if let Err(cmd_error) = operation {
        println!("{}", cmd_error);
        -2
    } else {
        0
    }
}

fn main() {
    exit(run_peroxs());
}
