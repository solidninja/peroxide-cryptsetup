#![deny(warnings)]
#![deny(bare_trait_objects)]
#[warn(unused_must_use)]
extern crate docopt;
extern crate env_logger;
extern crate errno;
extern crate peroxide_cryptsetup;
extern crate uuid;

#[macro_use]
extern crate log;

#[macro_use]
extern crate prettytable;

#[macro_use]
extern crate serde_derive;

use std::env;
use std::path::PathBuf;
use std::process::exit;
use std::str::FromStr;

use docopt::Docopt;
use log::Level;

use peroxide_cryptsetup::context::{
    Context, DeviceOps, DiskEnrolmentParams, EntryParams, FormatContainerParams, MainContext,
};
use peroxide_cryptsetup::db::{DbEntryType, DbType, PeroxideDb, YubikeyEntryType};

mod operation;
use operation::{PathOrUuid, Result};

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

static USAGE: &'static str = "
Usage:
    peroxs enroll keyfile <keyfile> <device-or-uuid>... --iteration-ms=<iteration-ms> [--backup-db=<backup-db>] [--name=<name>] [at <db>]
    peroxs enroll keyfile <keyfile> new [(--luks1|--luks2)] --cipher=<cipher> --hash=<hash> --key-bits=<key-bits> <device-or-uuid>... --iteration-ms=<iteration-ms> [--backup-db=<backup-db>] [--name=<name>] [--luks-version=<luks-version>] [at <db>]
    peroxs enroll passphrase <device-or-uuid>... --iteration-ms=<iteration-ms> [--backup-db=<backup-db>] [--name=<name>] [at <db>]
    peroxs enroll passphrase new [(--luks1|--luks2)] --cipher=<cipher> --hash=<hash> --key-bits=<key-bits> <device-or-uuid>... --iteration-ms=<iteration-ms> [--backup-db=<backup-db>] [--name=<name>]  [--luks-version=<luks-version>] [at <db>]
    peroxs enroll yubikey [hybrid] --slot=<slot> <device-or-uuid>... --iteration-ms=<iteration-ms> [--backup-db=<backup-db>] [--name=<name>] [at <db>]
    peroxs enroll yubikey [hybrid] --slot=<slot> new [(--luks1|--luks2)] --cipher=<cipher> --hash=<hash> --key-bits=<key-bits> <device-or-uuid>... --iteration-ms=<iteration-ms> [--backup-db=<backup-db>] [--name=<name>]  [--luks-version=<luks-version>] [at <db>]
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
    --version                               Show the version of peroxs
    --force                                 Force certain operations (e.g. formatting)

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
    flag_force: bool,
    flag_cipher: Option<String>,
    flag_hash: Option<String>,
    flag_key_bits: Option<usize>,
    flag_backup_db: Option<String>,
    flag_iteration_ms: Option<u32>,
    flag_name: Option<String>,
    flag_slot: Option<u8>,
    flag_luks1: bool,
    flag_luks2: bool,
}

impl Args {
    fn paths_or_uuids(&self) -> Result<Vec<PathOrUuid>> {
        self.arg_device_or_uuid
            .as_ref()
            .expect("expecting device paths or uuids")
            .iter()
            .map(|s| PathOrUuid::from_str(&s))
            .collect::<Result<Vec<_>>>()
    }
}

fn db_path(args: &Args) -> Result<PathBuf> {
    args.arg_db
        .as_ref()
        .map(PathBuf::from)
        .map(Ok) // gwah!
        .unwrap_or_else(|| {
            PeroxideDb::default_location()
                .map_err(From::from)
                .map_err(From::<peroxide_cryptsetup::context::Error>::from)
        })
}

fn cipher_mode(args: &Args) -> (String, String) {
    // split cipher string by - e.g. 'aes-xts-plain' becomes 'aes' and 'xts-plain'
    let res = args
        .flag_cipher
        .as_ref()
        .expect("Must supply cipher")
        .splitn(2, '-')
        .collect::<Vec<_>>();
    if res.len() != 2 {
        panic!("Expect cipher to be splittable by name-mode e.g. aes-xts-plain")
    } else {
        (res[0].to_string(), res[1].to_string())
    }
}

fn format_params(args: &Args) -> FormatContainerParams {
    let (cipher, cipher_mode) = cipher_mode(args);
    let hash = args.flag_hash.as_ref().expect("Must supply hash").to_string();
    let key_bits = args.flag_key_bits.expect("Must supply key bits");
    let iteration_ms = args.flag_iteration_ms.expect("iteration millis");

    if args.flag_luks1 {
        FormatContainerParams::Luks1 {
            iteration_ms,
            cipher,
            cipher_mode,
            hash,
            mk_bits: key_bits,
        }
    } else {
        let parallel_threads = 4; // todo configurable
        let memory_kb = 512000; // 512MB todo configurable
        let pbkdf2_iterations = 1_000_000; // todo configurable, benchmarked

        FormatContainerParams::Luks2 {
            cipher,
            cipher_mode,
            mk_bits: key_bits,
            hash,
            time_ms: iteration_ms,
            iterations: pbkdf2_iterations,
            max_memory_kb: memory_kb,
            parallel_threads,
            sector_size: None,
            data_alignment: None,
            save_label_in_header: false, // todo configurable
        }
    }
}

fn yubikey_entry_params(args: &Args) -> EntryParams {
    let entry_type = if args.cmd_hybrid {
        YubikeyEntryType::HybridChallengeResponse
    } else {
        YubikeyEntryType::ChallengeResponse
    };
    let slot = args.flag_slot.expect("Yubikey slot should be specified");
    EntryParams::Yubikey(slot, entry_type)
}

fn enroll_params(args: &Args) -> Result<DiskEnrolmentParams> {
    let entry_type = db_entry_type(args);

    let entry_params = match entry_type {
        DbEntryType::Passphrase => EntryParams::Passphrase,
        DbEntryType::Keyfile => {
            let path = PathBuf::from(args.arg_keyfile.as_ref().expect("keyfile path"));
            EntryParams::Keyfile(path)
        }
        DbEntryType::Yubikey => yubikey_entry_params(args),
    };

    let format_container_opt = if args.cmd_new { Some(format_params(args)) } else { None };

    Ok(DiskEnrolmentParams {
        name: args.flag_name.clone(),
        entry: entry_params,
        format_container: format_container_opt,
        force_format: args.flag_force,
        iteration_ms: args.flag_iteration_ms.expect("iteration millis"),
    })
}

fn db_entry_type(args: &Args) -> DbEntryType {
    match args {
        _ if args.cmd_passphrase => DbEntryType::Passphrase,
        _ if args.cmd_keyfile => DbEntryType::Keyfile,
        _ if args.cmd_yubikey => DbEntryType::Yubikey,
        _ => panic!("BUG: Unrecognised entry type!"),
    }
}

fn enroll<C: Context + DeviceOps>(args: &Args, ctx: &C) -> Result<()> {
    let enroll_params = enroll_params(args)?;
    let backup_context = args.flag_backup_db.as_ref().map(PathBuf::from).map(MainContext::new);
    let device_paths_or_uuids = args.paths_or_uuids()?;

    operation::enroll::enroll::<C, MainContext>(
        &ctx,
        operation::enroll::Params {
            device_paths_or_uuids,
            backup_context,
            params: enroll_params,
        },
    )
}

fn open<C: Context + DeviceOps>(args: &Args, ctx: &C) -> Result<()> {
    let device_paths_or_uuids = args.paths_or_uuids()?;
    let name = args.flag_name.clone();

    operation::open::open(
        ctx,
        operation::open::Params {
            device_paths_or_uuids,
            name,
        },
    )
}

fn register<C: Context>(args: &Args, ctx: &C) -> Result<()> {
    let device_paths_or_uuids = args.paths_or_uuids()?;
    let name = args.flag_name.clone();
    let keyfile = args.arg_keyfile.as_ref().map(PathBuf::from);
    let entry_type = db_entry_type(&args);

    operation::register::register(
        ctx,
        operation::register::Params {
            device_paths_or_uuids,
            entry_type,
            keyfile,
            name,
        },
    )
}

fn perform_operation(args: &Args) -> Result<()> {
    let db_type_opt: Option<DbType> = args.arg_db_type.as_ref().map(|s| match s.as_ref() {
        "operation" => DbType::Operation,
        "backup" => DbType::Backup,
        _ => panic!("Unrecognised DB type"),
    });
    let db_path = db_path(args)?;
    let ctx = MainContext::new(db_path);

    match args {
        _ if args.cmd_enroll => enroll(args, &ctx),
        _ if args.cmd_init => operation::newdb::newdb(&ctx, operation::newdb::Params(db_type_opt.expect("db type"))),
        _ if args.cmd_list => operation::list::list(
            &ctx,
            operation::list::Params {
                only_available: !args.flag_all,
            },
        ),
        _ if args.cmd_open => open(args, &ctx),
        _ if args.cmd_register => register(args, &ctx),
        _ => panic!("BUG: Unknown command!"),
    }
}

fn run_peroxs() -> i32 {
    env_logger::init();
    if log_enabled!(Level::Debug) {
        // enable cryptsetup tracing
        MainContext::trace_on();
    }

    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.argv(env::args().into_iter()).deserialize())
        .unwrap_or_else(|e| e.exit());

    if args.flag_version {
        println!("peroxs {}", VERSION);
        0
    } else {
        match perform_operation(&args) {
            Ok(_) => 0,
            Err(e) => {
                println!("ERROR: {}", e);
                1
            }
        }
    }
}

fn main() {
    exit(run_peroxs());
}
