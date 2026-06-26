#!/bin/sh

. ./functions.sh

echo "external-transport (test-owned TCP socket) ls test"

echo -n "Testing prog_ls_external on root of share ... "
./prog_ls_external "${TESTURL}/" > /dev/null || failure
success

exit 0
