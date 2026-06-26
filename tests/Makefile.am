AM_CPPFLAGS = -I${srcdir}/../include -I${srcdir}/../include/smb2 \
	"-D_U_=__attribute__((unused))" \
	"-D_R_(A,B)=__attribute__((format(printf,A,B)))"
AM_CFLAGS = $(WARN_CFLAGS)
LDADD = ../lib/libsmb2.la

noinst_PROGRAMS = prog_ls prog_mkdir prog_rmdir prog_cat \
	prog_cat_cancel smb2-dcerpc-coder-test
noinst_PROGRAMS += metastat-0202-censored
noinst_PROGRAMS += prog_ls_external
noinst_PROGRAMS += prog_mock
noinst_PROGRAMS += prog_external_exchange

prog_ls_external_SOURCES = prog_ls_external.c \
	external_tcp_transport.c external_tcp_transport.h

prog_mock_SOURCES = prog_mock.c \
	mock_transport.c mock_transport.h recorded_exchange.h

# The full-exchange program links BOTH fixtures: it selects the in-memory mock
# or the test-owned TCP transport at runtime (argv), so the one binary runs the
# headline test two ways (network-free CI + live server).
prog_external_exchange_SOURCES = prog_external_exchange.c \
	mock_transport.c mock_transport.h recorded_exchange.h \
	external_tcp_transport.c external_tcp_transport.h

EXTRA_PROGRAMS = ld_sockerr
CLEANFILES = ld_sockerr.o ld_sockerr.so

ld_sockerr_SOURCES = ld_sockerr.c
ld_sockerr_CFLAGS = $(AM_CFLAGS) -fPIC

bin_SCRIPTS = ld_sockerr.so

ld_sockerr.o: ld_sockerr-ld_sockerr.o
	$(LIBTOOL) --mode=link $(CC) -o $@ $^

ld_sockerr.so: ld_sockerr.o
	$(CC) -shared -o ld_sockerr.so ld_sockerr.o -ldl

T = `ls test_*.sh`

test: $(noinst_PROGRAMS) $(bin_SCRIPTS)
	for TEST in $(T); do \
		echo "Running $$TEST"; \
		echo "--------------"; \
		sh $$TEST || exit 1; \
		echo "--------------"; \
		echo; \
	done
