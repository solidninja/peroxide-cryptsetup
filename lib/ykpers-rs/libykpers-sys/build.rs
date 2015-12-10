extern crate pkg_config;

fn main() {
    pkg_config::Config::new().statik(true).find("ykpers-1").unwrap();
}
