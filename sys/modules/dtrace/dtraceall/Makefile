# $FreeBSD: releng/12.0/sys/modules/dtrace/dtraceall/Makefile 332122 2018-04-06 17:35:35Z brooks $

SYSDIR?=	${SRCTOP}/sys

KMOD=		dtraceall
SRCS=		dtraceall.c opt_nfs.h

CFLAGS+=	-I${SYSDIR}

.include <bsd.kmod.mk>

CFLAGS+=	-include ${SYSDIR}/cddl/compat/opensolaris/sys/debug_compat.h
