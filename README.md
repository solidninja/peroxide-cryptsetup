[![pipeline status](https://gitlab.com/solidninja/peroxide-cryptsetup/badges/main/pipeline.svg)](https://gitlab.com/solidninja/peroxide-cryptsetup/commits/main)
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

(Copied from the clap-generated usage):

```
USAGE:
    peroxs [OPTIONS] <SUBCOMMAND>

OPTIONS:
    -d, --database <DATABASE>
            The database to use[default: peroxs-db.json]
            [aliases: db]

    -h, --help
            Print help information

    -V, --version
            Print version information

SUBCOMMANDS:
    enroll
            Enroll a new or existing LUKS disk(s) in the database (adding a new keyslot)
    help
            Print this message or the help of the given subcommand(s)
    init
            Initialize a new peroxide-db database
    list
            List disks enrolled in a database
    open
            Open enrolled LUKS disk(s)
    register
            Register an existing entry in the database (without adding a new keyslot)

```

#### `enroll`

```
USAGE:
    peroxs enroll [OPTIONS] <SUBCOMMAND>

OPTIONS:
    -d, --database <DATABASE>
            The database to use[default: peroxs-db.json]
            [aliases: db]

    -h, --help
            Print help information

SUBCOMMANDS:
    help
            Print this message or the help of the given subcommand(s)
    keyfile
            Enroll using a keyfile
    passphrase
            Enroll using a passphrase
    yubikey
            Enroll using a Yubikey token
```

#### `init`

```
USAGE:
    peroxs init [OPTIONS] <DB_TYPE>

ARGS:
    <DB_TYPE>
            Database type to enroll[possible values: operation, backup]

OPTIONS:
    -d, --database <DATABASE>
            The database to use[default: peroxs-db.json]
            [aliases: db]

    -h, --help
            Print help information
```

#### `list`

```
USAGE:
    peroxs list [OPTIONS]

OPTIONS:
        --all
            List all devices in database, regardless of whether they can be found to be attached to
            the system currently

    -d, --database <DATABASE>
            The database to use[default: peroxs-db.json]
            [aliases: db]

    -h, --help
            Print help information
```

#### `open`

```
USAGE:
    peroxs open [OPTIONS] [DEVICE_OR_UUID]...

ARGS:
    <DEVICE_OR_UUID>...
            The path(s) to the device or the LUKS UUID(s) of the device

OPTIONS:
    -d, --database <DATABASE>
            The database to use[default: peroxs-db.json]
            [aliases: db]

    -h, --help
            Print help information

    -n, --name <NAME>
            Override name specified in database (if any) when activating the device
```

#### `register`

```
USAGE:
    peroxs register [OPTIONS] <SUBCOMMAND>

OPTIONS:
    -d, --database <DATABASE>
            The database to use[default: peroxs-db.json]
            [aliases: db]

    -h, --help
            Print help information

SUBCOMMANDS:
    help
            Print this message or the help of the given subcommand(s)
    keyfile
            Register an existing keyfile
    passphrase
            Register an existing passphrase
```

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
