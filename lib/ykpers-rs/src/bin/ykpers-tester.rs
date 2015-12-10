extern crate ykpers_rs;

use ykpers_rs::*;

fn main() {
    let k = YubikeyDevice::new().unwrap();
    let stat = k.get_status().unwrap();
    println!("Version: {:?}", stat.get_version_triple());
}
