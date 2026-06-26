# Test programs for libsmb2.
#
# This file builds the network-bound external-transport fixture so it compiles
# under CMake. The .sh harness that drives it needs a live SMB server (via
# tests/setup.local), so the test is NOT registered as a CTest here; full CI
# wiring (including the network-free in-memory mock) lands in a later issue.
# The autotools build (tests/Makefile.am) is authoritative for this fixture.

add_executable(prog_ls_external
               prog_ls_external.c
               external_tcp_transport.c)
target_link_libraries(prog_ls_external smb2 ${CORE_LIBRARIES})
add_dependencies(prog_ls_external smb2)
