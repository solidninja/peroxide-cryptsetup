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
    printf -- '--name systemd-peroxs-%%k %s start ' $(command -v systemctl)
    printf -- 'peroxs@$env{ID_FS_UUID}.service"\n'
    echo 'LABEL="peroxs_end"'
} >> /etc/udev/rules.d/71-peroxs.rules.new

# The UUID that peroxs expects is a v4 hyphenated UUID but /dev/disk/by-id/... does not contain hyphens
uuid="$PEROXS_ROOT_UUID"
while [ "$uuid" != "${uuid#*-}" ]; do uuid=${uuid%%-*}${uuid#*-}; done

# Finish when UUID is opened
{
    printf -- '[ -e /dev/disk/by-id/dm-uuid-CRYPT-LUKS?-*%s*-* ] || exit 1\n' ${uuid}
} >> $hookdir/initqueue/finished/91-peroxs.sh

# Emergency when disk is not found
{
    printf -- '[ -e /dev/disk/by-uuid/*%s* ] || ' $PEROXS_ROOT_UUID
    printf -- 'warn "crypto LUKS UUID "%s" not found"\n' $PEROXS_ROOT_UUID
} >> $hookdir/emergency/91-peroxs.sh

mv /etc/udev/rules.d/71-peroxs.rules.new /etc/udev/rules.d/71-peroxs.rules
