#!/bin/sh -xe

cleanup() {
    if [ -d "$OPDIR" ]; then
        echo "NOT Removing OPDIR $OPDIR"
        #rm -rf $OPDIR
    fi
}
trap cleanup EXIT

echo "Starting the newdb-and-open scenario"

export RUST_LOG=peroxide_cryptsetup=trace,cryptsetup_rs=trace
export OPDIR=`mktemp -d`
export RUST_BACKTRACE=full

peroxs="`pwd`/target/debug/peroxs"
[ ! -f $peroxs ] && echo "ERROR: peroxs not found in $peroxs" && exit 1

echo "Using $OPDIR"

cd $OPDIR

dd if=/dev/urandom of=disk-image bs=1M count=20
echo "Made disk-image"

$peroxs init backup --db backup.json
echo "Made db of type backup"

dd if=/dev/urandom of=keyfile1.key count=256
echo "Made keyfile1"

dd if=/dev/urandom of=keyfile2.key count=256
echo "Made keyfile2"

$peroxs enroll keyfile \
  -2 \
  --db backup.json \
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
  keyfile1.key disk-image
echo "Enrolled keyfile1 db"

$peroxs init operation
echo "Made db2 of type operation"

$peroxs enroll keyfile \
  --backup-db backup.json \
  --iteration-ms 200 \
  --argon2-iterations 1000 \
  --argon2-memory-kb 1024 \
  --argon2-parallel-threads 1 \
  keyfile2.key disk-image
echo "Enrolled in db2"
