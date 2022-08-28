#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

extern crate libc;

use libc::{c_char, c_int, c_uchar, c_uint, c_ushort, c_void, size_t};

// FIXME: do we need repr(packed) here becasue ykdef.h defined #pragma pack(push, 1)?
// ykdef.h
#[repr(i32)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum SLOT {
    CONFIG = 1,
    NAV = 2,
    CONFIG2 = 3,
    UPDATE1 = 4,
    SWAP = 6,
    NDEF = 8,
    NDEF2 = 9,
    DEVICE_SERIAL = 0x10,
    DEVICE_CONFIG = 0x11,
    SCAN_MAP = 0x12,
    YK4_CAPABILITIES = 0x13,
    CHAL_OTP1 = 0x20,
    CHAL_OTP2 = 0x28,
    CHAL_HMAC1 = 0x30,
    CHAL_HMAC2 = 0x38,
    WRITE_FLAG = 0x80,
}

#[repr(i32)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum RESP {
    ITEM_MASK = 0x07,
    TIMEOUT_WAIT_MASK = 0x1f,
    TIMEOUT_WAIT_FLAG = 0x20,
    PENDING_FLAG = 0x80,
}

pub const DUMMY_REPORT_WRITE: i32 = 0x8f;
pub const NEO_STARTUP_BUSY: i32 = 0x9f;
pub const SHA1_MAX_BLOCK_SIZE: usize = 64;
pub const SHA1_DIGEST_SIZE: usize = 20;
pub const SERIAL_NUMBER_SIZE: usize = 4;

pub const SLOT_DATA_SIZE: usize = 64;

#[repr(C)]
pub struct frame_st {
    pub payload: [c_uchar; SLOT_DATA_SIZE],
    pub slot: c_uchar,
    pub crc: c_ushort,
    filler: [c_uchar; 3],
}

pub const UID_SIZE: usize = 6;

#[repr(C)]
pub struct ticket_st {
    uid: [c_uchar; UID_SIZE],
    useCtr: c_ushort,
    tstpl: c_ushort,
    sessionCtr: c_uchar,
    rnd: c_ushort,
    crc: c_ushort,
}

pub const TICKET_ACT_HIDRPT: i32 = 0x8000;
pub const TICKET_CTR_MASK: i32 = 0x7fff;

pub const FIXED_SIZE: usize = 16;
pub const KEY_SIZE: usize = 16;
pub const KEY_SIZE_OATH: usize = 20;
pub const ACC_CODE_SIZE: usize = 6;

#[repr(C)]
pub struct config_st {
    fixed: [c_uchar; FIXED_SIZE],
    uid: [c_uchar; UID_SIZE],
    key: [c_uchar; KEY_SIZE],
    accCode: [c_uchar; ACC_CODE_SIZE],
    fixedSize: c_uchar,
    extFlags: c_uchar,
    tktFlags: c_uchar,
    cfgFlag: c_uchar,
    rfu: [c_uchar; 2],
    crc: c_ushort,
}

// Yubikey 1
#[repr(i32)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum TKTFLAG_YK1 {
    TAB_FIRST = 0x01,
    APPEND_TAB1 = 0x02,
    APPEND_TAB2 = 0x04,
    APPEND_DELAY1 = 0x08,
    APPEND_DELAY2 = 0x10,
    APPEND_CR = 0x20,
}

// Yubikey 2
#[repr(i32)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum TKTFLAG_YK2 {
    TAB_FIRST = TKTFLAG_YK1::TAB_FIRST as i32,
    APPEND_TAB1 = TKTFLAG_YK1::APPEND_TAB1 as i32,
    APPEND_TAB2 = TKTFLAG_YK1::APPEND_TAB2 as i32,
    APPEND_DELAY1 = TKTFLAG_YK1::APPEND_DELAY1 as i32,
    APPEND_DELAY2 = TKTFLAG_YK1::APPEND_DELAY2 as i32,
    APPEND_CR = TKTFLAG_YK1::APPEND_CR as i32,
    PROTECT_CFG2 = 0x80,
}

// Yubikey 2.1+
#[repr(i32)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum TKTFLAG_YK21 {
    TAB_FIRST = TKTFLAG_YK1::TAB_FIRST as i32,
    APPEND_TAB1 = TKTFLAG_YK1::APPEND_TAB1 as i32,
    APPEND_TAB2 = TKTFLAG_YK1::APPEND_TAB2 as i32,
    APPEND_DELAY1 = TKTFLAG_YK1::APPEND_DELAY1 as i32,
    APPEND_DELAY2 = TKTFLAG_YK1::APPEND_DELAY2 as i32,
    APPEND_CR = TKTFLAG_YK1::APPEND_CR as i32,
    PROTECT_CFG2 = TKTFLAG_YK2::PROTECT_CFG2 as i32,
    OATH_HOTP = 0x40,
}

// Yubikey 2.2+
#[repr(i32)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum TKTFLAG_YK22 {
    TAB_FIRST = TKTFLAG_YK1::TAB_FIRST as i32,
    APPEND_TAB1 = TKTFLAG_YK1::APPEND_TAB1 as i32,
    APPEND_TAB2 = TKTFLAG_YK1::APPEND_TAB2 as i32,
    APPEND_DELAY1 = TKTFLAG_YK1::APPEND_DELAY1 as i32,
    APPEND_DELAY2 = TKTFLAG_YK1::APPEND_DELAY2 as i32,
    APPEND_CR = TKTFLAG_YK1::APPEND_CR as i32,
    PROTECT_CFG2 = TKTFLAG_YK2::PROTECT_CFG2 as i32,
    CHAL_RESP = 0x40,
}

// Yubikey 1
#[repr(i32)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum CFGFLAG_YK1 {
    SEND_REF = 0x01,
    PACING_10MS = 0x04,
    PACING_20MS = 0x08,
    STATIC_TICKET = 0x20,
    // Yubikey 1 only
    TICKET_FIRST = 0x02,
    ALLOW_HIDTRIG = 0x10,
}

// Yubikey 2
#[repr(i32)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum CFGFLAG_YK2 {
    SEND_REF = CFGFLAG_YK1::SEND_REF as i32,
    PACING_10MS = CFGFLAG_YK1::PACING_10MS as i32,
    PACING_20MS = CFGFLAG_YK1::PACING_20MS as i32,
    STATIC_TICKET = CFGFLAG_YK1::STATIC_TICKET as i32,
    SHORT_TICKET = 0x02,
    STRONG_PW1 = 0x10,
    STRONG_PW2 = 0x40,
    MAN_UPDATE = 0x80,
}

// Yubikey 2.1+
#[repr(i32)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum CFGFLAG_YK21 {
    SEND_REF = CFGFLAG_YK1::SEND_REF as i32,
    PACING_10MS = CFGFLAG_YK1::PACING_10MS as i32,
    PACING_20MS = CFGFLAG_YK1::PACING_20MS as i32,
    STATIC_TICKET = CFGFLAG_YK1::STATIC_TICKET as i32,
    MAN_UPDATE = CFGFLAG_YK2::MAN_UPDATE as i32,
    OATH_HOTP8 = 0x02,
    OATH_FIXED_MODHEX1 = 0x10,
    OATH_FIXED_MODHEX2 = 0x40,
    // OATH_FIXED_MODHEX = 0x50,
    OATH_FIXED_MASK = 0x50,
}

// Yubikey 2.2+
#[repr(i32)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum CFGFLAG_YK22 {
    SEND_REF = CFGFLAG_YK1::SEND_REF as i32,
    MAN_UPDATE = CFGFLAG_YK2::MAN_UPDATE as i32,
    OATH_HOTP8 = CFGFLAG_YK21::OATH_HOTP8 as i32,
    OATH_FIXED_MODHEX1 = CFGFLAG_YK21::OATH_FIXED_MODHEX1 as i32,
    OATH_FIXED_MODHEX2 = CFGFLAG_YK21::OATH_FIXED_MODHEX2 as i32,
    OATH_FIXED_MASK = CFGFLAG_YK21::OATH_FIXED_MASK as i32,
    CHAL_YUBICO = 0x20,
    CHAL_HMAC = 0x22,
    HMAC_LT64 = 0x04,
    CHAL_BTN_TRIG = 0x08,
}

#[repr(i32)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum EXTFLAG {
    SERIAL_BTN_VISIBLE = 0x01,
    SERIAL_USB_VISIBLE = 0x02,
    SERIAL_API_VISIBLE = 0x04,
    // 2.3 flags only
    USE_NUMERIC_KEYPAD = 0x08,
    FAST_TRIG = 0x10,
    ALLOW_UPDATE = 0x20,
    DORMANT = 0x40,
    // 2.4/3.1 flags only
    LED_INV = 0x80,
}

pub const TKTFLAG_UPDATE_MASK: i32 = TKTFLAG_YK1::TAB_FIRST as i32
    | TKTFLAG_YK1::APPEND_TAB1 as i32
    | TKTFLAG_YK1::APPEND_TAB2 as i32
    | TKTFLAG_YK1::APPEND_DELAY1 as i32
    | TKTFLAG_YK1::APPEND_DELAY2 as i32
    | TKTFLAG_YK1::APPEND_CR as i32;
pub const CFGFLAG_UPDATE_MASK: i32 = CFGFLAG_YK1::PACING_10MS as i32 | CFGFLAG_YK1::PACING_20MS as i32;
pub const EXTFLAG_UPDATE_MASK: i32 = EXTFLAG::SERIAL_BTN_VISIBLE as i32
    | EXTFLAG::SERIAL_USB_VISIBLE as i32
    | EXTFLAG::SERIAL_API_VISIBLE as i32
    | EXTFLAG::USE_NUMERIC_KEYPAD as i32
    | EXTFLAG::FAST_TRIG as i32
    | EXTFLAG::ALLOW_UPDATE as i32
    | EXTFLAG::DORMANT as i32
    | EXTFLAG::LED_INV as i32;

pub const NDEF_DATA_SIZE: usize = 54;

#[repr(C)]
pub struct ndef_st {
    pub len: c_uchar,
    pub tpe: c_uchar,
    pub data: [c_uchar; NDEF_DATA_SIZE],
    pub curAccCode: [c_uchar; ACC_CODE_SIZE],
}

// Navigation not mapped

#[repr(C)]
pub struct device_config_st {
    mode: c_uchar,
    crTimeout: c_uchar,
    autoEjectTime: c_ushort,
}

#[repr(i32)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum MODE {
    OTP = 0x00,
    CCID = 0x01,
    OTP_CCID = 0x02,
    U2F = 0x03,
    OTP_U2F = 0x04,
    U2F_CCID = 0x05,
    OTP_U2F_CCID = 0x06,
    MASK = 0x07,
    FLAG_EJECT = 0x80,
}

pub const DEFAULT_CHAL_TIMEOUT: i32 = 15;

pub const SCAN_MAP: &'static [u8] = b"cbdefghijklnrtuvCBDEFGHIJKLNRTUV0123456789!\t\r";
pub const SHIFT_FLAG: i32 = 0x80;

#[repr(C)]
pub struct status_st {
    pub versionMajor: c_uchar,
    pub versionMinor: c_uchar,
    pub versionBuild: c_uchar,
    pub pgmSeq: c_ushort,
    pub touchLevel: c_ushort,
}

#[repr(i32)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum TOUCHLEVEL_BIT {
    CONFIG1_VALID = 0x01,
    CONFIG2_VALID = 0x02,
    CONFIG1_TOUCH = 0x04,
    CONFIG2_TOUCH = 0x08,
    CONFIG_LED_INV = 0x10,
    CONFIG_STATUS_MASK = 0x1f,
}

pub const MODHEX_MAP: &'static [u8] = b"cbdefghijklnrtuv";

pub const YUBICO_VID: i32 = 0x1050;

#[repr(i32)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum PID {
    YUBIKEY = 0x0010,
    NEO_OTP = 0x0110,
    NEO_OTP_CCID = 0x0111,
    NEO_CCID = 0x0112,
    NEO_U2F = 0x0113,
    NEO_OTP_U2F = 0x0114,
    NEO_U2F_CCID = 0x0115,
    NEO_OTP_U2F_CCID = 0x0116,
    // Yubikey 4
    YK4_OTP = 0x0401,
    YK4_U2F = 0x0402,
    YK4_OTP_U2F = 0x0403,
    YK4_CCID_ = 0x0404,
    YK4_OTP_CCID = 0x0405,
    YK4_U2F_CCID = 0x0406,
    YK4_OTP_U2F_CCID = 0x0407,
    PLUS_U2F_OTP = 0x0410,
}

#[repr(i32)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum YK4_TAG {
    CAP = 0x01,
    SERIAL = 0x02,
}

#[repr(i32)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum YK4_CAPA1 {
    OTP = 0x01,
    U2F = 0x02,
    CCID = 0x04,
}

// ykpbkdf2.h
pub type prf_fn = extern "C" fn(*const c_char, size_t, *const c_char, size_t, *mut u8, size_t) -> c_int;

#[repr(C)]
pub struct yk_prf_method {
    pub output_size: size_t,
    pub prf_fn: prf_fn,
}

extern "C" {
    pub fn yk_hmac_sha1(
        key: *const c_char,
        key_len: size_t,
        text: *const c_char,
        text_len: size_t,
        output: *mut u8,
        output_size: size_t,
    ) -> c_int;
    pub fn yk_pbkdf2(
        passphrase: *const c_char,
        salt: *const c_uchar,
        salt_len: size_t,
        iterations: c_uint,
        dk: *mut c_uchar,
        dklen: size_t,
        prf_method: *mut yk_prf_method,
    ) -> c_int;
}

// ykstatus.h
extern "C" {
    pub fn ykds_alloc() -> *mut yk_status_st;
    pub fn ykds_free(st: *mut yk_status_st);

    // ignore ykds_static()

    pub fn ykds_version_major(st: *const yk_status_st) -> c_int;
    pub fn ykds_version_minor(st: *const yk_status_st) -> c_int;
    pub fn ykds_version_build(st: *const yk_status_st) -> c_int;
    pub fn ykds_pgm_seq(st: *const yk_status_st) -> c_int;
    pub fn ykds_touch_level(st: *const yk_status_st) -> c_int;
}

// ykcore.h
pub enum yk_key_st {}
pub enum yk_status_st {}
pub enum yk_ticket_st {}
pub enum yk_config_st {}
pub enum yk_nav_st {}
pub enum yk_frame_st {}
// FIXME did we pick the right ndef_st here?
// pub enum ndef_st { }
pub enum yk_device_config_st {}

extern "C" {
    pub fn yk_init() -> c_int;
    pub fn yk_release() -> c_int;

    pub fn yk_open_first_key() -> *mut yk_key_st;
    pub fn yk_close_key(k: *mut yk_key_st) -> c_int;

    pub fn yk_get_status(k: *mut yk_key_st, status: *mut yk_status_st) -> c_int;
    pub fn yk_check_firmware_version(k: *mut yk_key_st) -> c_int;
    pub fn yk_check_firmware_version2(status: *mut yk_status_st) -> c_int;
    pub fn yk_get_serial(yk: *mut yk_key_st, slot: u8, flags: c_uint, serial: *mut c_uint) -> c_int;
    pub fn yk_wait_for_key_status(
        yk: *mut yk_key_st,
        slot: u8,
        flags: c_uint,
        max_time_ms: c_uint,
        logic_and: bool,
        mask: c_uchar,
        last_data: *mut c_uchar,
    ) -> c_int;
    pub fn yk_read_response_from_key(
        yk: *mut yk_key_st,
        slot: u8,
        flags: c_uint,
        buf: *mut c_void,
        bufsize: c_uint,
        expect_bytes: c_uint,
        bytes_read: *mut c_uint,
    ) -> c_int;

    pub fn yk_write_command(k: *mut yk_key_st, cfg: *mut yk_config_st, command: u8, acc_code: *mut c_uchar) -> c_int;
    pub fn yk_write_config(k: *mut yk_key_st, cfg: *mut yk_config_st, confnum: c_int, acc_code: *mut c_uchar) -> c_int;
    pub fn yk_write_ndef(yk: *mut yk_key_st, ndef: *mut ndef_st) -> c_int;
    pub fn yk_write_ndef2(yk: *mut yk_key_st, ndef: *mut ndef_st, confnum: c_int) -> c_int;
    pub fn yk_write_device_config(yk: *mut yk_key_st, device_config: *mut yk_device_config_st) -> c_int;
    pub fn yk_write_scan_map(yk: *mut yk_key_st, scan_map: *mut c_uchar) -> c_int;
    pub fn yk_write_to_key(yk: *mut yk_key_st, slot: u8, buf: *const c_void, bufcount: c_int) -> c_int;
    pub fn yk_challenge_response(
        yk: *mut yk_key_st,
        yk_cmd: u8,
        may_block: c_int,
        challenge_len: c_uint,
        challenge: *const c_uchar,
        response_len: c_uint,
        response: *mut c_uchar,
    ) -> c_int;

    pub fn yk_force_key_update(yk: *mut yk_key_st) -> c_int;
    pub fn yk_get_key_vid_pid(yk: *mut yk_key_st, vid: *mut c_int, pid: *mut c_int) -> c_int;
    pub fn yk_get_capabilities(
        yk: *mut yk_key_st,
        slot: u8,
        flags: c_uint,
        capabilities: *mut c_uchar,
        len: *mut c_uint,
    ) -> c_int;

    pub fn _yk_errno_location() -> *mut c_int;
    pub fn yk_strerror(errno: c_int) -> *const c_char;
    pub fn yk_usb_strerror() -> *const c_char;

    // ignore yk_endian_swap_16
}

pub fn yk_errno() -> c_int {
    unsafe { *_yk_errno_location() }
}

#[repr(i32)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum YK_ERR {
    EUSBERR = 0x01,
    EWRONGSIZE = 0x02,
    EWRITEERR = 0x03,
    ETIMEOUT = 0x04,
    ENOKEY = 0x05,
    EFIRMWARE = 0x06,
    ENOMEM = 0x07,
    ENOSTATUS = 0x08,
    ENOTYETIMPL = 0x09,
    ECHECKSUM = 0x0a,
    EWOULDBLOCK = 0x0b,
    EINVALIDCMD = 0x0c,
    EMORETHANONE = 0x0d,
    ENODATA = 0x0e,
}

pub const YK_FLAG_MAYBLOCK: i32 = 0x01 << 16;
pub const YK_CRC_OK_RESIDUAL: i32 = 0xf0b8;
