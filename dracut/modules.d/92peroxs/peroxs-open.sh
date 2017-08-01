#!/bin/sh -xe

uuid=$1
# FIXME - bug in peroxs where $uuid only is not working for some reason...
# FIXME - bug somewhere? which means that rd.break=initqueue is practically required as the tty only allows a single
# FIXME     character to be entered before proceeding to open the disk
exec /usr/bin/peroxs open /dev/disk/by-uuid/${uuid} at /etc/peroxs-rootfs.json