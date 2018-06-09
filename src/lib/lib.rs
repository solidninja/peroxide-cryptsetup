#![deny(warnings)]
#[warn(unused_must_use)]
#[macro_use]
extern crate serde_derive;

extern crate cryptsetup_rs;
extern crate errno;
extern crate libc;
extern crate serde;
extern crate serde_json;
extern crate termios;
extern crate uuid;

extern crate log;

extern crate term;

#[macro_use]
extern crate prettytable;

pub mod context;
pub mod db;
mod io;
pub mod model;
pub mod operation;

#[cfg(feature = "yubikey")]
mod yubikey;

#[cfg(feature = "yubikey")]
extern crate ykpers_rs;

#[cfg(feature = "yubikey_hybrid")]
extern crate sodiumoxide;

#[cfg(test)]
extern crate tempfile;

#[cfg(test)]
extern crate tempdir;

#[cfg(test)]
extern crate env_logger;

#[cfg(test)]
#[macro_use(expect)]
extern crate expectest;
