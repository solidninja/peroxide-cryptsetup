#!/bin/sh

# called by dracut
check() {
    require_binaries peroxs || return 1

    return 255
}

# called by dracut
depends() {
    echo crypt
}

# called by dracut
install() {
    inst_multiple peroxs

    inst_multiple /etc/peroxs-rootfs.json

    inst_script "$moddir"/peroxs-open.sh /sbin/peroxs-open
    inst_simple "$moddir/peroxs@.service" ${systemdsystemunitdir}/peroxs@.service

    inst_hook cmdline 10 "$moddir/parse-peroxs.sh"

    dracut_need_initqueue
}