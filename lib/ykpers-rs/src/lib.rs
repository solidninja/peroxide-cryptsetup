extern crate libykpers_sys;
extern crate libc;

use std::sync::{Once, ONCE_INIT};
use std::sync::atomic::{AtomicIsize, ATOMIC_ISIZE_INIT, Ordering};
use std::result;

use libykpers_sys as ffi;

static FFI_INIT: Once = ONCE_INIT;
static FFI_INIT_RESULT: AtomicIsize = ATOMIC_ISIZE_INIT;
static MIN_VERSION_CHAL_RESP: Version = (2, 2, 0);

pub type Result<T> = result::Result<T, Error>;
pub type Version = (i32, i32, i32);

pub const SHA1_BLOCK_LENGTH: usize = ffi::SHA1_MAX_BLOCK_SIZE;
pub const SHA1_RESPONSE_LENGTH: usize = ffi::SHA1_DIGEST_SIZE;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum ValidationError {
    InvalidSlot,
    MinimumVersionNotMet {
        expected: Version,
        got: Version,
    },
}


#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum Error {
    Validation(ValidationError),
    UsbError,
    YkError(ffi::YK_ERR),
    Unknown(i32),
}

impl Error {
    fn from(res: i32) -> Result<()> {
        match res {
            0 => Ok(()),
            x if x == ffi::YK_ERR::EUSBERR as i32 => Err(Error::UsbError),
            // TODO - this is probably better with another crate
            x if x == ffi::YK_ERR::EWRONGSIZE as i32 => Err(Error::YkError(ffi::YK_ERR::EWRONGSIZE)),
            x if x == ffi::YK_ERR::EWRITEERR as i32 => Err(Error::YkError(ffi::YK_ERR::EWRITEERR)),
            x if x == ffi::YK_ERR::ETIMEOUT as i32 => Err(Error::YkError(ffi::YK_ERR::ETIMEOUT)),
            x if x == ffi::YK_ERR::ENOKEY as i32 => Err(Error::YkError(ffi::YK_ERR::ENOKEY)),
            x if x == ffi::YK_ERR::EFIRMWARE as i32 => Err(Error::YkError(ffi::YK_ERR::EFIRMWARE)),
            x if x == ffi::YK_ERR::ENOMEM as i32 => Err(Error::YkError(ffi::YK_ERR::ENOMEM)),
            x if x == ffi::YK_ERR::ENOSTATUS as i32 => Err(Error::YkError(ffi::YK_ERR::ENOSTATUS)),
            x if x == ffi::YK_ERR::ENOTYETIMPL as i32 => Err(Error::YkError(ffi::YK_ERR::ENOTYETIMPL)),
            x if x == ffi::YK_ERR::ECHECKSUM as i32 => Err(Error::YkError(ffi::YK_ERR::ECHECKSUM)),
            x if x == ffi::YK_ERR::EWOULDBLOCK as i32 => Err(Error::YkError(ffi::YK_ERR::EWOULDBLOCK)),
            x if x == ffi::YK_ERR::EMORETHANONE as i32 => Err(Error::YkError(ffi::YK_ERR::EMORETHANONE)),
            x if x == ffi::YK_ERR::ENODATA as i32 => Err(Error::YkError(ffi::YK_ERR::ENODATA)),
            unknown => Err(Error::Unknown(unknown)),
        }
    }

    fn from_zero_err(res: i32) -> Result<()> {
        if res == 0 {
            Error::from(ffi::yk_errno()).map(|_| panic!("BUG: expecting error for zero return code"))
        } else {
            Ok(())
        }
    }
}

struct NullPtr;

impl NullPtr {
    fn wrap_err<T>(t: *mut T) -> Result<*mut T> {
        if t.is_null() {
            Error::from(ffi::yk_errno()).map(|_| panic!("No error returned for null pointer!"))
        } else {
            Ok(t)
        }
    }
}


fn yk_init() -> Result<()> {
    FFI_INIT.call_once(|| {
        let res = unsafe { ffi::yk_init() };
        FFI_INIT_RESULT.store(res as isize, Ordering::Release);
    });
    let res = FFI_INIT_RESULT.load(Ordering::Acquire);
    Error::from_zero_err(res as i32)
}

pub struct YubikeyDevice {
    key: *mut ffi::yk_key_st,
}

impl Drop for YubikeyDevice {
    fn drop(&mut self) {
        // TODO - check return code?
        unsafe { ffi::yk_close_key(self.key) };
    }
}

pub struct YubikeyDeviceStatus {
    status: *mut ffi::yk_status_st,
}

impl Drop for YubikeyDeviceStatus {
    fn drop(&mut self) {
        unsafe { ffi::ykds_free(self.status) }
    }
}

pub trait YubikeyStatus {
    fn get_version_triple(&self) -> Version;
    fn get_programming_seq(&self) -> i32;
    fn get_touch_level(&self) -> i32;
}

pub trait Yubikey {
    type Status;

    fn new() -> Result<Self> where Self: Sized;
    fn get_status(&self) -> Result<Self::Status> where Self::Status: YubikeyStatus;
}

impl Yubikey for YubikeyDevice {
    type Status = YubikeyDeviceStatus;

    fn new() -> Result<YubikeyDevice> {
        yk_init().and_then(|_| NullPtr::wrap_err(unsafe { ffi::yk_open_first_key() }).map(|key| YubikeyDevice { key: key }))
    }

    fn get_status(&self) -> Result<Self::Status> {
        NullPtr::wrap_err(unsafe { ffi::ykds_alloc() })
            .and_then(|status| Error::from_zero_err(unsafe { ffi::yk_get_status(self.key, status) }).map(|_| status))
            .map(|status| YubikeyDeviceStatus { status: status })
    }
}

impl YubikeyStatus for YubikeyDeviceStatus {
    fn get_version_triple(&self) -> Version {
        let major = unsafe { ffi::ykds_version_major(self.status) };
        let minor = unsafe { ffi::ykds_version_minor(self.status) };
        let build = unsafe { ffi::ykds_version_build(self.status) };
        (major, minor, build)
    }

    fn get_programming_seq(&self) -> i32 {
        unsafe { ffi::ykds_pgm_seq(self.status) }
    }

    fn get_touch_level(&self) -> i32 {
        unsafe { ffi::ykds_touch_level(self.status) }
    }
}

pub struct ChallengeResponseParams {
    pub is_hmac: bool,
    pub slot: u8,
}

pub trait ChallengeResponse {
    fn challenge_response(&mut self,
                          params: ChallengeResponseParams,
                          challenge: &[u8],
                          response: &mut [u8; SHA1_BLOCK_LENGTH])
                          -> Result<()>;
}

impl ChallengeResponse for YubikeyDevice {
    fn challenge_response(&mut self,
                          params: ChallengeResponseParams,
                          challenge: &[u8],
                          response: &mut [u8; SHA1_BLOCK_LENGTH])
                          -> Result<()> {

        // check version of yubikey
        let status = try!(self.get_status());
        let version_triple = status.get_version_triple();
        if version_triple < MIN_VERSION_CHAL_RESP {
            return Err(Error::Validation(ValidationError::MinimumVersionNotMet {
                expected: MIN_VERSION_CHAL_RESP,
                got: version_triple,
            }));
        }

        let may_block = 1;
        let yk_cmd = match params.slot {
            1 => {
                if params.is_hmac {
                    ffi::SLOT::CHAL_HMAC1
                } else {
                    ffi::SLOT::CHAL_OTP1
                }
            }
            2 => {
                if params.is_hmac {
                    ffi::SLOT::CHAL_HMAC2
                } else {
                    ffi::SLOT::CHAL_OTP2
                }
            }
            _ => return Err(Error::Validation(ValidationError::InvalidSlot)),
        };
        let res = unsafe {
            ffi::yk_challenge_response(self.key,
                                       yk_cmd as u8,
                                       may_block,
                                       challenge.len() as u32,
                                       challenge.as_ptr(),
                                       response.len() as u32,
                                       response.as_mut_ptr())
        };

        Error::from_zero_err(res as i32)
    }
}
