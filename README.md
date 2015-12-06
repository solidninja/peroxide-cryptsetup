[![Build Status](https://travis-ci.org/solidninja/peroxide-cryptsetup.svg?branch=master)](https://travis-ci.org/solidninja/peroxide-cryptsetup)

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

```
$ cargo build                               # This creates the peroxs executable
$ cd /secure/key/storage/location           # Location for your backup keys
$ peroxs init backup                        # Creates peroxide-cryptsetup database, a json file called peroxs-db.json
# Enroll the device
$ peroxs enroll keyfile secret.key /dev/your-disk --name="awesome" --iteration-ms=1000
# Open the device
$ peroxs open /dev/your-disk
```

## Roadmap

There's no official roadmap, but have a look in [TASKS.todo](TASKS.todo) for a list of current tasks.

## Contributing

`peroxide-cryptsetup` is the work of its contributors and is a free software project licensed under the 
GPLv3 or later. 

If you would like to contribute, please follow the [C4](http://rfc.zeromq.org/spec:22) process. 