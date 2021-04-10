// #![deny(warnings)]
// #![deny(bare_trait_objects)]
// #[warn(unused_must_use)]
extern crate clap;
extern crate env_logger;
extern crate errno;
#[macro_use]
extern crate log;
extern crate peroxide_cryptsetup;
#[macro_use]
extern crate prettytable;
extern crate serde_derive;
extern crate uuid;

extern crate ksni;

use clap::{AppSettings, Clap, ValueHint};
use ksni::menu::{StandardItem, SubMenu};
use log::Level;
use peroxide_cryptsetup::context::{DeviceOps, MainContext, PeroxideDbOps};
use peroxide_cryptsetup::db::{DbEntry, PeroxideDb};
use std::panic;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::Arc;
use uuid::Uuid;
use vec1::Vec1;

#[derive(Clap, Debug)]
#[clap(author, about, version,
global_setting = AppSettings::ColoredHelp,
global_setting = AppSettings::VersionlessSubcommands,
max_term_width = 120)]
struct Opts {
    #[clap(flatten)]
    global: GlobalOpts,
}

#[derive(Clap, Debug)]
struct GlobalOpts {
    #[clap(short, long, visible_aliases = & ["db"], about = "The database to use", default_value = "peroxs-db.json", value_hint = ValueHint::FilePath, global = true)]
    database: PathBuf,
}

#[derive(Debug)]
struct MyTray {
    ctx: MainContext,
    db: PeroxideDb,
    // TODO: remove these
    selected_option: usize,
    checked: bool,
}

impl MyTray {
    fn activate(&mut self, uuid: &Uuid) {
        info!("trying to activate uuid {}", uuid);

        if let Some(entry) = self.db.entries.iter().find(|&e| e.uuid() == uuid) {
            match self.ctx.activate::<PathBuf>(entry, None, None) {
                Ok(name) => info!("activated uuid {} with name {}", uuid, name),
                Err(ex) => error!("could not activate uuid {} with error {:?}", uuid, ex),
            }
        } else {
            warn!("could not find entry with uuid {} to activate", uuid);
        }
    }
}

fn to_active_entry(entry: &DbEntry) -> ksni::MenuItem<MyTray> {
    SubMenu {
        label: entry.volume_id().name.as_ref().unwrap_or(&"?".to_string()).into(),
        icon_name: "drive-harddisk-encrypted-symbolic".into(),
        submenu: vec![StandardItem {
            label: "Deactivate".into(),
            icon_name: "media-eject".into(),

            ..Default::default()
        }
        .into()],
        ..Default::default()
    }
    .into()
}

fn active_entries(db: &PeroxideDb) -> Vec<ksni::MenuItem<MyTray>> {
    db.entries
        .iter()
        .filter(|e| MainContext::is_active(e, None))
        .map(|e| to_active_entry(e))
        .collect()
}

fn to_available_entry(entry: &DbEntry) -> ksni::MenuItem<MyTray> {
    let uuid = entry.uuid().clone();
    SubMenu {
        label: entry.volume_id().name.as_ref().unwrap_or(&"?".to_string()).into(),
        icon_name: "drive-harddisk-encrypted-symbolic".into(),
        submenu: vec![StandardItem {
            label: "Open".into(),
            activate: Box::new(move |this: &mut MyTray| this.activate(&uuid)),
            ..Default::default()
        }
        .into()],
        ..Default::default()
    }
    .into()
}

fn available_entries(db: &PeroxideDb) -> Vec<ksni::MenuItem<MyTray>> {
    db.entries
        .iter()
        .filter(|e| MainContext::is_present(e) && !MainContext::is_active(e, None))
        .map(|e| to_available_entry(e))
        .collect()
}

impl ksni::Tray for MyTray {
    fn icon_name(&self) -> String {
        "drive-harddisk-encrypted".into()
    }
    fn title(&self) -> String {
        "peroxs-tray".into()
    }
    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::*;

        let mut res = Vec::new();

        // active devices
        let mut active = active_entries(&self.db);
        if !active.is_empty() {
            res.push(
                StandardItem {
                    label: "Active disks".into(),
                    enabled: false,
                    ..Default::default()
                }
                .into(),
            );
            res.append(&mut active_entries(&self.db));
            res.push(MenuItem::Sepatator);
        }

        // available devices
        let mut present = available_entries(&self.db);
        if !present.is_empty() {
            res.push(
                StandardItem {
                    label: "Available disks".into(),
                    enabled: false,
                    icon_name: "drive-multidisk".into(),
                    ..Default::default()
                }
                .into(),
            );
            res.append(&mut available_entries(&self.db));
            res.push(MenuItem::Sepatator);
        }

        // end
        res.push(
            StandardItem {
                label: "Exit".into(),
                icon_name: "application-exit".into(),
                activate: Box::new(|_| std::process::exit(0)),
                ..Default::default()
            }
            .into(),
        );

        res

        // vec![
        //     SubMenu {
        //         label: "a".into(),
        //         submenu: vec![
        //             SubMenu {
        //                 label: "a1".into(),
        //                 submenu: vec![
        //                     StandardItem {
        //                         label: "a1.1".into(),
        //                         ..Default::default()
        //                     }
        //                         .into(),
        //                     StandardItem {
        //                         label: "a1.2".into(),
        //                         ..Default::default()
        //                     }
        //                         .into(),
        //                 ],
        //                 ..Default::default()
        //             }
        //                 .into(),
        //             StandardItem {
        //                 label: "a2".into(),
        //                 ..Default::default()
        //             }
        //                 .into(),
        //         ],
        //         ..Default::default()
        //     }
        //         .into(),
        //     MenuItem::Sepatator,
        //     RadioGroup {
        //         selected: self.selected_option,
        //         select: Box::new(|this: &mut Self, current| {
        //             this.selected_option = current;
        //         }),
        //         options: vec![
        //             RadioItem {
        //                 label: "Option 0".into(),
        //                 ..Default::default()
        //             },
        //             RadioItem {
        //                 label: "Option 1".into(),
        //                 ..Default::default()
        //             },
        //             RadioItem {
        //                 label: "Option 2".into(),
        //                 ..Default::default()
        //             },
        //         ],
        //         ..Default::default()
        //     }
        //         .into(),
        //     CheckmarkItem {
        //         label: "Checkable".into(),
        //         checked: self.checked,
        //         activate: Box::new(|this: &mut Self| this.checked = !this.checked),
        //         ..Default::default()
        //     }
        //         .into(),
        //     StandardItem {
        //         label: "Exit".into(),
        //         icon_name: "application-exit".into(),
        //         activate: Box::new(|_| std::process::exit(0)),
        //         ..Default::default()
        //     }
        //         .into(),
        // ]
    }
}

fn setup_prereqs() {
    env_logger::init();
    if log_enabled!(Level::Debug) {
        // enable cryptsetup tracing
        MainContext::trace_on();
    }

    // panic will be our downfall
    let orig_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        orig_hook(panic_info);
        exit(1);
    }));
}

fn main() {
    setup_prereqs();

    let opts: Opts = Opts::parse();
    let ctx = MainContext::new(opts.global.database.clone());
    if let Ok(db) = ctx.open_db() {
        let service = ksni::TrayService::new(MyTray {
            ctx,
            db,
            selected_option: 0,
            checked: false,
        });
        // let handle = service.handle();
        service.spawn();

        // std::thread::sleep(std::time::Duration::from_secs(5));
        // // We can modify the tray
        // handle.update(|tray: &mut MyTray| {
        //     tray.checked = true;
        // });

        // Run forever
        loop {
            std::thread::park();
        }
    } else {
        print!("Could not open database {}", &opts.global.database.display());
        exit(1);
    }
}
