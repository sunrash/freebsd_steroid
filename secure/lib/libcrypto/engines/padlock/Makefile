# $FreeBSD: releng/12.0/secure/lib/libcrypto/engines/padlock/Makefile 338844 2018-09-20 21:59:47Z jkim $

SHLIB_NAME?=	padlock.so

SRCS=	e_padlock.c
.if ${MACHINE_CPUARCH} == "amd64"
SRCS+=	e_padlock-x86_64.S
.elif ${MACHINE_CPUARCH} == "i386"
SRCS+=	e_padlock-x86.S
.endif

.include <bsd.lib.mk>

.PATH:	${.CURDIR:H:H}/${MACHINE_CPUARCH}
