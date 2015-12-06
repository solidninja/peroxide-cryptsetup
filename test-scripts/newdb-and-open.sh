#!/bin/sh -xe

cleanup() {
    if [ -d "$OPDIR" ]; then
        echo "Removing OPDIR $OPDIR"
        # rm -rf $OPDIR 
    fi
}
trap cleanup EXIT

echo "Starting the newdb-and-open scenario"

export RUST_LOG=peroxide_cryptsetup=debug,cryptsetup_rs=debug
# export OPDIR=`mktemp -d`
export OPDIR=/tmp/vlad/tmp.mLPj8PMnk3
# FIXME temporary
mkdir -p $OPDIR
rm -f $OPDIR/peroxs-db.json

peroxs="`pwd`/target/debug/peroxs"
[ ! -f $peroxs ] && echo "ERROR: peroxs not found in $peroxs" && exit 1 

echo "Using $OPDIR"

cd $OPDIR

dd if=/dev/urandom of=disk-image bs=1M count=10
echo "Made disk-image"

$peroxs init backup
echo "Made db of type backup"

dd if=/dev/urandom of=keyfile.key count=256
echo "Made keyfile"

$peroxs enroll keyfile keyfile.key new --cipher aes-xts-plain --hash sha256 --key-bits 256 disk-image --iteration-ms=200 --name "test-disk"
echo "Enrolled db"

# TODO - need to ensure name is ok before enrolling it?
$peroxs open disk-image
