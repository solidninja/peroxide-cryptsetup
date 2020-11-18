#!/bin/sh -xe

cleanup() {
    if [ -d "$OPDIR" ]; then
        echo "Removing OPDIR $OPDIR"
        rm -rf $OPDIR
    fi
}
trap cleanup EXIT

echo "Starting the newdb-and-open scenario"

export RUST_LOG=peroxide_cryptsetup=trace,cryptsetup_rs=trace
export OPDIR=`mktemp -d`

peroxs="`pwd`/target/debug/peroxs"
[ ! -f $peroxs ] && echo "ERROR: peroxs not found in $peroxs" && exit 1

echo "Using $OPDIR"

cd $OPDIR

dd if=/dev/urandom of=disk-image bs=1M count=20
echo "Made disk-image"

$peroxs init backup
echo "Made db of type backup"

dd if=/dev/urandom of=keyfile.key count=256
echo "Made keyfile"

$peroxs enroll keyfile \
  -2 \
  --format \
  --cipher aes-xts-plain \
  --hash sha256 \
  --key-bits 256 \
  --name "test-disk" \
  --iteration-ms 200 \
  --argon2-iterations 1000 \
  --argon2-memory-kb 1024 \
  --argon2-parallel-threads 1 \
  --save-label-in-header \
  keyfile.key disk-image
echo "Enrolled db"

# TODO - need to ensure name is ok before enrolling it?
$peroxs open disk-image
