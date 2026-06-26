# Test programs for libsmb2.
#
# This file builds two external-transport fixtures:
#
#  * prog_ls_external -- carries the SMB2 byte stream over a real, test-owned
#    TCP socket. Its .sh harness needs a live SMB server (via tests/setup.local),
#    so it is NOT registered as a CTest here.
#
#  * prog_mock -- the network-free in-memory mock: it drives a real negotiate
#    exchange entirely through the external-transport callbacks over in-memory
#    byte queues, with no socket and no server. It IS registered as a CTest
#    (mock_inmemory) because it is safe to run unconditionally in CI.
#
# The autotools build (tests/Makefile.am) remains authoritative for the fixtures.

add_executable(prog_ls_external
               prog_ls_external.c
               external_tcp_transport.c)
target_link_libraries(prog_ls_external smb2 ${CORE_LIBRARIES})
add_dependencies(prog_ls_external smb2)

add_executable(prog_mock
               prog_mock.c
               mock_transport.c)
target_link_libraries(prog_mock smb2 ${CORE_LIBRARIES})
add_dependencies(prog_mock smb2)
add_test(NAME mock_inmemory COMMAND prog_mock)

#  * prog_external_exchange -- the headline #15 test: a full connect_share +
#    directory listing + teardown driven purely through the external callbacks.
#    The one binary runs two ways (argv-selected); only the network-free
#    in-memory mode is registered as a CTest. It links both fixtures.
add_executable(prog_external_exchange
               prog_external_exchange.c
               mock_transport.c
               external_tcp_transport.c)
target_link_libraries(prog_external_exchange smb2 ${CORE_LIBRARIES})
add_dependencies(prog_external_exchange smb2)
add_test(NAME external_exchange_inmemory
         COMMAND prog_external_exchange --inmemory)
