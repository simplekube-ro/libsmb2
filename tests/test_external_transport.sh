#!/bin/sh

# Headline external-transport decoupling test (issue #15).
#
# Runs prog_external_exchange TWO ways against the same binary:
#
#  1. --inmemory : ALWAYS. Network-free full SMB exchange (connect_share +
#     directory list + teardown) driven purely through the external-transport
#     callbacks over in-memory byte queues -- no server, no socket. This leg
#     deliberately does NOT source ./setup.local, so it runs unconditionally in
#     CI. We inline the OK/FAILED helpers here for the same reason.
#
#  2. <smb2-url> : ONLY when ./setup.local exists. The same program over a
#     test-owned TCP socket to the live server (the genuine signed crypto path).
#     Mirrors the gating that functions.sh enforces for the server-backed tests.

echo "external-transport full-exchange test (issue #15)"

echo -n "Running prog_external_exchange --inmemory ... "
if ./prog_external_exchange --inmemory; then
    echo "[OK]"
else
    echo "[FAILED]"
    exit 1
fi

if [ -f ./setup.local ]; then
    # Server-backed leg: only attempted when a fixture is configured.
    . ./setup.local
    echo -n "Running prog_external_exchange on ${TESTURL}/ ... "
    if ./prog_external_exchange "${TESTURL}/" > /dev/null; then
        echo "[OK]"
    else
        echo "[FAILED]"
        exit 1
    fi
else
    echo "tcp leg skipped (no tests/setup.local; needs a live SMB server)"
fi

exit 0
