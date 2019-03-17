# $FreeBSD: releng/12.0/sys/modules/dtrace/fbt/Makefile 314651 2017-03-04 10:10:17Z ngie $

SYSDIR?=	${SRCTOP}/sys

.PATH:		${SYSDIR}/cddl/dev/fbt

KMOD=		fbt
SRCS=		fbt.c fbt_isa.c
SRCS+=		vnode_if.h

.if ${MACHINE_CPUARCH} == "amd64" || ${MACHINE_CPUARCH} == "i386"
CFLAGS+=	-I${SYSDIR}/cddl/dev/fbt/x86
.PATH:		${SYSDIR}/cddl/dev/fbt/x86
.else
CFLAGS+=	-I${SYSDIR}/cddl/dev/fbt/${MACHINE_CPUARCH}
.PATH:		${SYSDIR}/cddl/dev/fbt/${MACHINE_CPUARCH}
.endif

CFLAGS+=	-I${SYSDIR}/cddl/dev/fbt \
		-I${SYSDIR}/cddl/compat/opensolaris \
		-I${SYSDIR}/cddl/contrib/opensolaris/uts/common \
		-I${SYSDIR}

.include <bsd.kmod.mk>

CFLAGS+=	-include ${SYSDIR}/cddl/compat/opensolaris/sys/debug_compat.h
