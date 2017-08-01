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

    inst_hook cmdline 30 "$moddir/parse-peroxs.sh"

    dracut_need_initqueue
}