#![deny(warnings)]
#[warn(unused_must_use)]

extern crate rustc_serialize;
extern crate docopt;
extern crate peroxide_cryptsetup;

// TODO - improve the logging story?
extern crate env_logger;

use std::path::{Path, PathBuf};
use std::env;
use std::io;
use std::fs;
use std::process::exit;

use docopt::Docopt;

use peroxide_cryptsetup::model::{OpenOperation, EnrollOperation, NewDatabaseOperation, CryptOperation, PeroxideDb, DbLocation,
                                 DbEntryType, DbType, NewContainerParameters, YubikeyEntryType};
use peroxide_cryptsetup::context::MainContext;

static USAGE: &'static str = "
Usage:
    peroxs enroll (keyfile <keyfile> | passphrase | yubikey [hybrid] --slot=<slot>) [new --cipher=<cipher> --hash=<hash> --key-bits=<key-bits>] <device-or-uuid>... --iteration-ms=<iteration-ms> [--backup-db=<backup-db>] [--name=<name>] [at <db>] 
    peroxs init <db-type> [at <db>]
    peroxs open <device-or-uuid>... [--name=<name>] [at <db>]
    peroxs (--help | --version)

Actions:
    enroll                                  Enroll a new or existing LUKS disk(s) with a given key type and parameters 
    init                                    Create a new database of the specified type
    open                                    Open an existing LUKS disk(s) with parameters from the database

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

// FIXME: Adding :PathBuf below causes breakage, why?
#[derive(RustcDecodable, Debug)]
struct Args {
    cmd_init: bool,
    cmd_enroll: bool,
    cmd_new: bool,
    cmd_open: bool,
    cmd_keyfile: bool,
    cmd_passphrase: bool,
    cmd_yubikey: bool,
    cmd_hybrid: bool,
    cmd_at: bool,
    arg_db: Option<String>,
    arg_db_type: Option<DbType>,
    arg_device_or_uuid: Option<Vec<String>>,
    arg_keyfile: Option<String>,
    flag_version: bool, // TODO - implement!
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
    let db_path = try!(get_db_path(at_path));
    let db_type = try!(maybe_db_type.map(|t| Ok(t.clone()))
                                    .unwrap_or_else(|| get_db_type(&db_path)));
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
    let device_paths_or_uuids = maybe_paths.unwrap_or_else(|| panic!("expecting device paths or uuids"));
    let name = args.flag_name.clone();

    CryptOperation::Open(OpenOperation {
        context: context,
        device_paths_or_uuids: device_paths_or_uuids,
        name: name,
    })
}

fn get_operation(args: &Args) -> CryptOperation {
    // TODO: remove this line
    println!("{:?}", args);
    let db_location = get_db_location(args.arg_db.as_ref().map(PathBuf::from),
                                      args.arg_db_type.as_ref())
                          .unwrap_or_else(|err| panic!("expecting db location, error: {}", err));
    let context = MainContext::new(db_location);
    let maybe_paths = args.arg_device_or_uuid.clone();

    match args {
        _ if args.cmd_init => CryptOperation::NewDatabase(NewDatabaseOperation { context: context }),
        _ if args.cmd_enroll => _enroll_operation(args, context, maybe_paths),
        _ if args.cmd_open => _open_operation(args, context, maybe_paths),
        _ => panic!("BUG: Unrecognised operation!"),
    }
}

fn run_peroxs() -> i32 {
    env_logger::init().unwrap();
    // this enables verbose logging in the cryptsetup lib
    // TODO: remove this or move to feature flag
    MainContext::trace_on();

    let args: Args = Docopt::new(USAGE)
                         .and_then(|d| d.decode())
                         .unwrap_or_else(|e| e.exit());

    if let Err(reason) = get_operation(&args).perform() {
        println!("ERROR: {}", reason);
        -1
    } else {
        0
    }
}

fn main() {
    exit(run_peroxs());
}
