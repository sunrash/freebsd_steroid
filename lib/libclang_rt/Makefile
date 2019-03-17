# $FreeBSD: releng/12.0/lib/libclang_rt/Makefile 336437 2018-07-17 23:23:54Z imp $

.if ${MACHINE_CPUARCH} == "i386" || ${MACHINE_CPUARCH} == "amd64"
SUBDIR+=	include
SUBDIR+=	asan
SUBDIR+=	asan-preinit
SUBDIR+=	asan_cxx
SUBDIR+=	asan_dynamic
SUBDIR+=	safestack
SUBDIR+=	stats
SUBDIR+=	stats_client
.if ${MACHINE_CPUARCH} == "amd64"
SUBDIR+=	tsan
SUBDIR+=	tsan_cxx
.endif
SUBDIR+=	ubsan_minimal
SUBDIR+=	ubsan_standalone
SUBDIR+=	ubsan_standalone_cxx
.endif

.if ${MACHINE_CPUARCH} == "i386" || ${MACHINE_CPUARCH} == "amd64" || \
    ${MACHINE_CPUARCH} == "arm"
SUBDIR+=	profile
.endif

.include <bsd.subdir.mk>
