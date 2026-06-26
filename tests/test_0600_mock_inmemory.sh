#!/bin/sh

# Network-free in-memory mock transport test.
#
# Unlike the other tests in this directory, this one does NOT source
# ./setup.local and needs neither a live SMB server nor any socket: prog_mock
# drives a real libsmb2 negotiate exchange entirely through the external-
# transport callbacks over in-memory byte queues. It is therefore safe to run
# unconditionally in CI. We deliberately inline the success/failure helpers
# here instead of using functions.sh (which sources setup.local).

echo "pure in-memory loopback transport test (no sockets, no server)"

echo -n "Running prog_mock ... "
if ./prog_mock; then
    echo "[OK]"
else
    echo "[FAILED]"
    exit 1
fi

exit 0
