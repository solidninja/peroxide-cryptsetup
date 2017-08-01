#!/bin/sh

PEROXS_ROOT_UUID=$(getargs rd.peroxs.uuid -d rd_PEROXS_UUID)

# Rule for running `peroxs open` when disk with matching uuid is found
# TODO support multiple disks
{
    echo 'SUBSYSTEM!="block", GOTO="peroxs_end"'
    echo 'ACTION!="add|change", GOTO="peroxs_end"'
    printf -- 'ENV{ID_FS_TYPE}=="crypto_LUKS", '
    printf -- 'ENV{ID_FS_UUID}=="*%s*", ' ${PEROXS_ROOT_UUID}
    printf -- 'RUN+="%s --settled --unique --onetime ' $(command -v initqueue)
    printf -- '--name peroxs-open-%%k %s ' $(command -v peroxs)
    printf -- 'open $env{DEVNAME} at /etc/peroxs-rootfs.json"\n'
    echo 'LABEL="peroxs_end"'
} >> /etc/udev/rules.d/71-peroxs.rules.new

echo "DUMP contents of file:"
cat /etc/udev/rules.d/71-peroxs.rules.new


# Finish when UUID is opened
{
    printf -- '[ -e /dev/disk/by-id/dm-uuid-CRYPT-LUKS?-*%s*-* ] || exit 1\n' ${PEROXS_ROOT_UUID}
} >> $hookdir/initqueue/finished/91-peroxs.sh

mv /etc/udev/rules.d/71-peroxs.rules.new /etc/udev/rules.d/71-peroxs.rules
