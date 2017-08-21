[![Build Status](https://travis-ci.org/solidninja/peroxide-cryptsetup.png?branch=master)](https://travis-ci.org/solidninja/peroxide-cryptsetup)
[![crates.io Status](https://img.shields.io/crates/v/peroxide-cryptsetup.svg)](https://crates.io/crates/peroxide-cryptsetup)

_**peroxide-cryptsetup**_

* _(peroxide) a viscous liquid with strong oxidizing properties._

# peroxide-cryptsetup - cli utility for managing cryptsetup disks on Linux

_**WARNING: alpha quality**_

## Description

`peroxs` is a command-line utility for managing cryptsetup disks on Linux. More precisely,
it helps you to manage key enrollment for devices and add backup keys in case your operational keys get
lost. It only supports LUKS devices currently.

## Usage

Documentation is currently a bit light, but this will get you started:

* `cargo install peroxide-cryptsetup`

Alternatively, clone this repository and build from source:

 * `cargo build`
 * now `target/debug/peroxs` will be simply referred to as `peroxs`

### Enrolling your first disk

Enrollment is the term used throughout for adding a new keyslot to either an existing or new LUKS disk. 

Pick a block device (disk). We will use `/dev/your-disk` as an example.

 * `cd /secure/key/storage/location`
 * `peroxs init backup` (create the db)
 * `peroxs enroll keyfile secret.key /dev/your-disk --name=awesome --iteration-ms=1000`

The above assumes that `/dev/your-disk` has already been `cryptsetup luksFormat`ed. If you need to format
an entirely new device:

 * `peroxs enroll keyfile secret.key new --cipher aes-xts-plain --hash sha256 --key-bits 256 /dev/your-disk --name=awesome --iteration-ms=1000`

For more information on the values of `--cipher`, `--hash` and `--key-bits` see `man cryptsetup`.

### Open a device that is already enrolled

 * `cd /location/of/peroxs/db`
 * `peroxs open /dev/your-disk` (alternative, can use uuid of disk)

### Register an existing keyfile or passphrase for a disk

* `peroxs register keyfile secret.key /dev/your-disk --name=awesome`

### List disks in the database and their status

* `peroxs list --all`

### Full usage

_verbatim from [peroxs.rs](src/bin/peroxs.rs)_

```
Usage:
    peroxs enroll keyfile <keyfile> <device-or-uuid>... --iteration-ms=<iteration-ms> [--backup-db=<backup-db>] [--name=<name>] [at <db>]
    peroxs enroll keyfile <keyfile> new --cipher=<cipher> --hash=<hash> --key-bits=<key-bits> <device-or-uuid>... --iteration-ms=<iteration-ms> [--backup-db=<backup-db>] [--name=<name>] [at <db>]
    peroxs enroll passphrase <device-or-uuid>... --iteration-ms=<iteration-ms> [--backup-db=<backup-db>] [--name=<name>] [at <db>]
    peroxs enroll passphrase new --cipher=<cipher> --hash=<hash> --key-bits=<key-bits> <device-or-uuid>... --iteration-ms=<iteration-ms> [--backup-db=<backup-db>] [--name=<name>] [at <db>]
    peroxs enroll yubikey [hybrid] --slot=<slot> <device-or-uuid>... --iteration-ms=<iteration-ms> [--backup-db=<backup-db>] [--name=<name>] [at <db>]
    peroxs enroll yubikey [hybrid] --slot=<slot> new --cipher=<cipher> --hash=<hash> --key-bits=<key-bits> <device-or-uuid>... --iteration-ms=<iteration-ms> [--backup-db=<backup-db>] [--name=<name>] [at <db>]
    peroxs init <db-type> [at <db>]
    peroxs list [--all]
    peroxs open <device-or-uuid>... [--name=<name>] [at <db>]
    peroxs register keyfile <keyfile> <device-or-uuid>...  [--name=<name>] [at <db>]
    peroxs register passphrase <device-or-uuid>...  [--name=<name>] [at <db>]
    peroxs (--help | --version)

Actions:
    enroll                                  Enroll a new or existing LUKS disk(s) with a given key type and parameters 
    init                                    Create a new database of the specified type
    list                                    List disks that are in the database and available
    open                                    Open an existing LUKS disk(s) with parameters from the database
    register                                Add an existing keyfile/passphrase entry in the database for a LUKS disk(s)

Enrollment types:
    keyfile                                 An existing key file with randomness inside
    passphrase                              A password or passphrase
    yubikey                                 A Yubikey (combined with challenge)
    yubikey hybrid                          A Yubikey (combined with challenge) and a secondary passphrase

Arguments:
    <db>                                    The path to the database
    <db-type>                               The database type (used when creating). One of: operation,backup
    <device-or-uuid>                        The path to the device or the uuid of the device
    <keyfile>                               The path to the key file 

Options:
    --help                                  Show this message
    --version                               Show the version of peroxs

    --backup-db <backup-db>                 The path to the backup database to use (if any)
    -c <cipher>, --cipher <cipher>          Cipher to use for new LUKS container
    -i <ms>, --iteration-ms <ms>            Number of milliseconds to wait for the PBKDF2 function iterations
    -h <hash>, --hash <hash>                Hash function to use for new LUKS container
    -n <name>, --name <name>                Name for the device being enrolled
    -s <key-bits>, --key-bits <key-bits>    Number of key bits to use for new LUKS container
    -S <slot>, --slot <slot>                Slot in Yubikey to use
```

## Roadmap

There's no official roadmap, but have a look in [TASKS.todo](TASKS.todo) for a list of current tasks.

## Development

You will require the following packages installed:

* `libcryptsetup-devel`
* `libsodium-devel`
* `ykpers-devel`

(Your distribution's package names may vary)

## Contributing

`peroxide-cryptsetup` is the work of its contributors and is a free software project licensed under the 
GPLv3 or later. 

If you would like to contribute, please follow the [C4](http://rfc.zeromq.org/spec:22) process. 
