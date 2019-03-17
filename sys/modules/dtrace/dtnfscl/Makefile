# $FreeBSD: releng/12.0/sys/modules/dtrace/dtnfscl/Makefile 314651 2017-03-04 10:10:17Z ngie $

SYSDIR?=	${SRCTOP}/sys

.PATH:		${SYSDIR}/fs/nfsclient

KMOD=		dtnfscl
SRCS=		nfs_clkdtrace.c \
		vnode_if.h

CFLAGS+=	-I${SYSDIR}/cddl/compat/opensolaris \
		-I${SYSDIR}/cddl/contrib/opensolaris/uts/common \
		-I${SYSDIR}

.include <bsd.kmod.mk>

CFLAGS+=	-include ${SYSDIR}/cddl/compat/opensolaris/sys/debug_compat.h
