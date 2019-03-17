# $FreeBSD: releng/12.0/tools/tools/ncpus/Makefile 291738 2015-12-04 03:17:47Z bdrewery $

PROG=	ncpus
MAN=
SRCS=	ncpus.c acpi.c
.if ${MACHINE_ARCH} == "amd64" || ${MACHINE_ARCH} == "i386"
SRCS+=	biosmptable.c
.endif
BINDIR=	/usr/local/bin
WARNS?=	6

LIBADD=	devinfo

.include <bsd.prog.mk>
