# $FreeBSD: releng/12.0/secure/lib/libcrypto/engines/Makefile 339270 2018-10-09 21:28:26Z gjb $

SUBDIR=		capi
.if ${MACHINE_CPUARCH} == "amd64" || ${MACHINE_CPUARCH} == "i386"
SUBDIR+=	padlock
.endif
SUBDIR_PARALLEL=

.include <bsd.subdir.mk>
