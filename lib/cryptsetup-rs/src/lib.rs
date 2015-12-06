#![deny(warnings)]

extern crate libcryptsetup_sys as raw;
extern crate libc;
extern crate errno;
extern crate uuid;
extern crate blkid_rs;

#[macro_use]
extern crate log;

pub mod device;
