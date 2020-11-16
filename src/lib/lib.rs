#![deny(warnings)]
#![deny(bare_trait_objects)]
#![warn(unused_must_use)]

extern crate cryptsetup_rs;
extern crate errno;
extern crate secstr;
extern crate serde;
extern crate serde_json;
extern crate ttypass;
extern crate uuid;

#[macro_use]
extern crate log;

#[cfg(feature = "pinentry")]
extern crate pinentry_rs;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate vec1;

#[cfg(feature = "yubikey_hybrid")]
extern crate sodiumoxide;

#[cfg(feature = "yubikey")]
extern crate ykpers_rs;

#[cfg(test)]
extern crate env_logger;

#[cfg(test)]
extern crate expectest;

#[cfg(test)]
extern crate tempfile;

pub mod context;
pub mod db;
pub mod device;
pub mod input;
