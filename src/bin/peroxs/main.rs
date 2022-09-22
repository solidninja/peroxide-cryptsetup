#![deny(warnings)]
#![deny(bare_trait_objects)]
#[warn(unused_must_use)]
#[macro_use]
extern crate log;
#[macro_use]
extern crate prettytable;

use std::convert::Infallible;
use std::path::PathBuf;
use std::process::exit;
use std::str::FromStr;

use clap::{value_parser, Args, Parser, Subcommand, ValueHint};
use log::Level;
use snafu::ErrorCompat;

use operation::{PathOrUuid, Result};
use peroxide_cryptsetup::context::{DiskEnrolmentParams, EntryParams, FormatContainerParams, MainContext};
use peroxide_cryptsetup::db::{DbEntryType, DbType, YubikeyEntryType};

mod operation;

#[derive(Parser, Debug)]
#[command(author, about, version, max_term_width = 120, disable_colored_help = false)]
struct Opts {
    #[command(subcommand)]
    subcmd: TopSubcommand,
    #[command(flatten)]
    global: GlobalOpts,
}

#[derive(Args, Debug)]
struct GlobalOpts {
    #[arg(short, long, visible_aliases = &["db"], long_help = "The database to use", default_value = "peroxs-db.json", value_hint = ValueHint::FilePath, global=true)]
    database: PathBuf,
}

#[derive(Subcommand, Debug)]
enum TopSubcommand {
    #[command(about = "Enroll a new or existing LUKS disk(s) in the database (adding a new keyslot)")]
    Enroll(EnrollCommand),
    #[command(about = "Initialize a new peroxide-db database")]
    Init(InitCommand),
    #[command(about = "List disks enrolled in a database")]
    List(ListCommand),
    #[command(about = "Open enrolled LUKS disk(s)")]
    Open(OpenCommand),
    #[command(about = "Register an existing entry in the database (without adding a new keyslot)")]
    Register(RegisterCommand),
}

#[derive(Parser, Debug)]
struct EnrollCommand {
    #[command(subcommand)]
    subcmd: EnrollSubcommand,
}

#[derive(Parser, Debug)]
enum EnrollSubcommand {
    #[command(about = "Enroll using a keyfile", disable_help_flag = true)]
    Keyfile(EnrollKeyfile),
    #[command(about = "Enroll using a passphrase", disable_help_flag = true)]
    Passphrase(EnrollPassphrase),
    #[cfg(feature = "yubikey")]
    #[command(about = "Enroll using a Yubikey token", disable_help_flag = true)]
    Yubikey(EnrollYubikey),
}

#[derive(Args, Debug)]
struct LuksFormatParams {
    #[arg(long, visible_alias = "new", long_help = "Format the LUKS container")]
    format: bool,
    #[arg(
        long,
        visible_alias = "force",
        long_help = "Force format the LUKS container",
        requires = "format"
    )]
    force_format: bool,
    #[arg(short='1', long, long_help ="Use LUKS version 1", groups=&["luks-version"])]
    luks1: bool,
    #[arg(short='2', long, long_help ="Use LUKS version 2 (default)", groups=&["luks-version"])]
    _luks2: bool, // todo: remove
    #[arg(
        short = 'i',
        long,
        long_help = "Number of milliseconds to wait for the PBKDF2 function iterations",
        default_value = "1000"
    )]
    iteration_ms: u32,
    #[arg(
        short = 's',
        long,
        long_help = "Number of key bits to use for new LUKS container",
        default_value = "512"
    )]
    key_bits: usize,
    #[arg(
        short = 'c',
        long,
        long_help = "Cipher to use for new LUKS container",
        default_value = "aes-xts-plain"
    )]
    cipher: String,
    #[arg(
        short = 'h',
        long,
        long_help = "Hash function to use for new LUKS container",
        default_value = "sha256"
    )]
    hash: String,
    #[arg(
        long,
        long_help = "Number of iterations for argon2",
        default_value = "1000000",
        conflicts_with = "luks1"
    )]
    argon2_iterations: u32,
    #[arg(
        long,
        long_help = "Number of parallel threads for argon2",
        default_value = "4",
        conflicts_with = "luks1"
    )]
    argon2_parallel_threads: u32,
    #[arg(
        long,
        long_help = "Memory to use for argon2",
        default_value = "512000",
        conflicts_with = "luks1"
    )]
    argon2_memory_kb: u32,
    #[arg(
        long,
        visible_alias = "save-label",
        long_help = "Save the name provide in the LUKS header",
        conflicts_with = "luks1",
        requires = "format"
    )]
    save_label_in_header: bool,
}

#[derive(Args, Debug)]
struct EnrollCommon {
    #[arg(long_help ="The path(s) to the device or the LUKS UUID(s) of the device", value_hint = ValueHint::FilePath)]
    device_or_uuid: Vec<PathOrUuid>,
    #[command(flatten)]
    format_params: LuksFormatParams,
    #[arg(short, long, long_help = "The name of the device in the database")]
    name: Option<String>,
    #[arg(long, long_help ="Path to another database that can be used to unlock the device", value_hint = ValueHint::FilePath, conflicts_with = "format")]
    backup_db: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct EnrollKeyfile {
    #[arg(long_help ="An existing key file with randomness inside", value_hint = ValueHint::FilePath)]
    keyfile: PathBuf,
    #[command(flatten)]
    common: EnrollCommon,
}

#[derive(Args, Debug)]
struct EnrollPassphrase {
    #[command(flatten)]
    common: EnrollCommon,
}

#[cfg(feature = "yubikey")]
#[derive(Args, Debug)]
struct EnrollYubikey {
    #[cfg(feature = "yubikey_hybrid")]
    #[arg(long, long_help = "Use the yubikey-hybrid key derivation mechanism")]
    hybrid: bool,
    #[arg(short='S', long, long_help ="Slot in yubikey to use", value_parser=value_parser!(u8).range(1..=2))]
    // todo: show possible values
    slot: u8,
    #[command(flatten)]
    common: EnrollCommon,
}

#[derive(Args, Debug)]
struct InitCommand {
    #[arg(long_help = "Database type to enroll")]
    db_type: DbType, // todo: show possible values
}

#[derive(Args, Debug)]
struct ListCommand {
    #[arg(
        long,
        long_help = "List all devices in database, regardless of whether they can be found to be attached to the system currently"
    )]
    all: bool,
}

#[derive(Args, Debug)]
struct OpenCommand {
    #[arg(
        short,
        long,
        long_help = "Override name specified in database (if any) when activating the device"
    )]
    name: Option<String>,
    #[arg(long_help ="The path(s) to the device or the LUKS UUID(s) of the device", value_hint = ValueHint::FilePath)]
    device_or_uuid: Vec<DiskReference>,
}

#[derive(Args, Debug)]
struct RegisterCommand {
    #[command(subcommand)]
    subcmd: RegisterSubcommand,
}

#[derive(Parser, Debug)]
enum RegisterSubcommand {
    #[command(about = "Register an existing keyfile")]
    Keyfile(RegisterKeyfile),
    #[command(about = "Register an existing passphrase")]
    Passphrase(RegisterPassphrase),
}

#[derive(Args, Debug)]
struct RegisterCommon {
    #[arg(long_help ="The path(s) to the device or the LUKS UUID(s) of the device", value_hint = ValueHint::FilePath)]
    device_or_uuid: Vec<PathOrUuid>,
    #[arg(short, long, long_help = "The name of the device in the database")]
    name: Option<String>,
}

#[derive(Args, Debug)]
struct RegisterKeyfile {
    #[arg(long_help ="Path to an existing keyfile", value_hint = ValueHint::FilePath)]
    keyfile: PathBuf,
    #[command(flatten)]
    common: RegisterCommon,
}

#[derive(Args, Debug)]
struct RegisterPassphrase {
    #[command(flatten)]
    common: RegisterCommon,
}

#[derive(Debug, Clone)]
pub struct DiskReference(String);

impl FromStr for DiskReference {
    type Err = Infallible;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(DiskReference(s.to_string()))
    }
}

fn cipher_mode(params: &LuksFormatParams) -> (String, String) {
    // split cipher string by - e.g. 'aes-xts-plain' becomes 'aes' and 'xts-plain'
    let res = params.cipher.splitn(2, '-').collect::<Vec<_>>();
    if res.len() != 2 {
        panic!("Expect cipher to be splittable by name-mode e.g. aes-xts-plain")
    } else {
        (res[0].to_string(), res[1].to_string())
    }
}

fn format_params(params: &LuksFormatParams) -> FormatContainerParams {
    let (cipher, cipher_mode) = cipher_mode(params);
    let hash = params.hash.clone();
    let key_bits = params.key_bits.clone();
    let iteration_ms = params.iteration_ms.clone();

    if params.luks1 {
        FormatContainerParams::Luks1 {
            iteration_ms,
            cipher,
            cipher_mode,
            hash,
            mk_bits: key_bits,
            uuid: None,
        }
    } else {
        FormatContainerParams::Luks2 {
            cipher,
            cipher_mode,
            mk_bits: key_bits,
            hash,
            time_ms: iteration_ms,
            iterations: params.argon2_iterations,
            max_memory_kb: params.argon2_memory_kb,
            parallel_threads: params.argon2_parallel_threads,
            sector_size: None,
            data_alignment: None,
            save_label_in_header: params.save_label_in_header,
            uuid: None,
            label: None,
            token_id: None,
        }
    }
}

fn enroll(cmd: EnrollCommand) -> Result<operation::enroll::Params<MainContext>> {
    // let backup_ctx = cmd.flag_backup_db.as_ref().map(PathBuf::from).map(MainContext::new);
    let (common, entry) = match cmd.subcmd {
        EnrollSubcommand::Keyfile(keyfile) => {
            let params = EntryParams::Keyfile(keyfile.keyfile);
            (keyfile.common, params)
        }
        EnrollSubcommand::Passphrase(passphrase) => {
            let params = EntryParams::Passphrase;
            (passphrase.common, params)
        }
        EnrollSubcommand::Yubikey(yubikey) => {
            let entry_type = if yubikey.hybrid {
                YubikeyEntryType::HybridChallengeResponse
            } else {
                YubikeyEntryType::ChallengeResponse
            };

            let params = EntryParams::Yubikey(yubikey.slot, entry_type);

            (yubikey.common, params)
        }
    };

    let format_params = format_params(&common.format_params);

    let params = DiskEnrolmentParams {
        name: common.name,
        entry,
        format: common.format_params.format,
        force_format: common.format_params.force_format,
        format_params,
        iteration_ms: common.format_params.iteration_ms,
    };

    let backup_context = common.backup_db.map(MainContext::new);

    Ok(operation::enroll::Params {
        device_paths_or_uuids: common.device_or_uuid,
        backup_context,
        params,
    })
}

fn list(cmd: ListCommand) -> Result<operation::list::Params> {
    Ok(operation::list::Params {
        only_available: !cmd.all,
    })
}

fn newdb(cmd: InitCommand) -> Result<operation::newdb::Params> {
    Ok(operation::newdb::Params(cmd.db_type))
}

fn open(cmd: OpenCommand) -> Result<operation::open::Params> {
    Ok(operation::open::Params {
        disk_references: cmd.device_or_uuid,
        name: cmd.name,
    })
}

fn register(cmd: RegisterCommand) -> Result<operation::register::Params> {
    let (common, entry_type, keyfile_opt) = match cmd.subcmd {
        RegisterSubcommand::Keyfile(keyfile) => (keyfile.common, DbEntryType::Keyfile, Some(keyfile.keyfile)),
        RegisterSubcommand::Passphrase(passphrase) => (passphrase.common, DbEntryType::Passphrase, None),
    };

    Ok(operation::register::Params {
        device_paths_or_uuids: common.device_or_uuid,
        entry_type,
        keyfile: keyfile_opt,
        name: common.name,
    })
}

fn run_peroxs() -> i32 {
    env_logger::init();
    if log_enabled!(Level::Debug) {
        // enable cryptsetup tracing
        MainContext::trace_on();
    }

    let opts: Opts = Opts::parse();
    let ctx = MainContext::new(opts.global.database);

    let res = match opts.subcmd {
        TopSubcommand::Enroll(cmd) => enroll(cmd).and_then(|p| operation::enroll::enroll(&ctx, p)),
        TopSubcommand::Init(cmd) => newdb(cmd).and_then(|p| operation::newdb::newdb(&ctx, p)),
        TopSubcommand::List(cmd) => list(cmd).and_then(|p| operation::list::list(&ctx, p)),
        TopSubcommand::Open(cmd) => open(cmd).and_then(|p| operation::open::open(&ctx, p)),
        TopSubcommand::Register(cmd) => register(cmd).and_then(|p| operation::register::register(&ctx, p)),
    };

    match res {
        Ok(_) => 0,
        Err(e) => {
            println!("ERROR: {}", e);
            if let Some(bt) = ErrorCompat::backtrace(&e) {
                eprintln!("{}", bt)
            }
            1
        }
    }
}

fn main() {
    exit(run_peroxs());
}
