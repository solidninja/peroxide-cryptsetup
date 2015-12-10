extern crate libykpers_sys;

use libykpers_sys::*;

fn main() {
    unsafe {
        // FIXME - how do we init safely? - perhaps look at how libsodium does it
        if yk_init() == 0 {
            panic!("Failed YK init");
        }
        let yk = yk_open_first_key();
        if yk.is_null() {
            panic!("failed to open first key!")
        }

        let stat = ykds_alloc();
        if stat.is_null() {
            panic!("failed to open stat!");
        }

        if (yk_get_status(yk, stat) == 0) {
            panic!("unable to get status!");
        }

        let major = ykds_version_major(stat);
        let minor = ykds_version_minor(stat);
        let build = ykds_version_build(stat);
        println!("Version: {}.{}.{}", major, minor, build);
    }
}
