extern crate libykpers_sys;

use std::sync::{Once, ONCE_INIT};
use std::sync::atomic::{AtomicIsize, ATOMIC_ISIZE_INIT, Ordering};
use std::result;

use libykpers_sys as ffi;

static FFI_INIT: Once = ONCE_INIT;
static FFI_INIT_RESULT: AtomicIsize = ATOMIC_ISIZE_INIT;

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum Error {
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
            // TODO - do we call yk_errno() here?
            Err(Error::Unknown(0))
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
        unsafe { ffi::yk_close_key(self.key) }
    }
}

pub struct YubikeyStatus {
    status: *mut ffi::yk_status_st,
}

impl Drop for YubikeyStatus {
    fn drop(&mut self) {
        unsafe { ffi::ykds_free(self.status) }
    }
}

impl YubikeyDevice {
    pub fn new() -> Result<YubikeyDevice> {
        yk_init().and_then(|_| NullPtr::wrap_err(unsafe { ffi::yk_open_first_key() }).map(|key| YubikeyDevice { key: key }))
    }

    pub fn get_status(&self) -> Result<YubikeyStatus> {
        NullPtr::wrap_err(unsafe { ffi::ykds_alloc() })
            .and_then(|status| Error::from_zero_err(unsafe { ffi::yk_get_status(self.key, status) }).map(|_| status))
            .map(|status| YubikeyStatus { status: status })
    }
}

impl YubikeyStatus {
    pub fn get_version_triple(&self) -> (i32, i32, i32) {
        let major = unsafe { ffi::ykds_version_major(self.status) };
        let minor = unsafe { ffi::ykds_version_minor(self.status) };
        let build = unsafe { ffi::ykds_version_build(self.status) };
        (major, minor, build)
    }

    pub fn get_programming_seq(&self) -> i32 {
        unsafe { ffi::ykds_pgm_seq(self.status) }
    }

    pub fn get_touch_level(&self) -> i32 {
        unsafe { ffi::ykds_touch_level(self.status) }
    }
}
