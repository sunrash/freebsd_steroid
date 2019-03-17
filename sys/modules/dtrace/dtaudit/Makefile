# $FreeBSD: releng/12.0/sys/modules/dtrace/dtaudit/Makefile 318440 2017-05-18 06:15:42Z ngie $

SYSDIR?=	${SRCTOP}/sys

.PATH:		${SYSDIR}/security/audit

KMOD=		dtaudit
SRCS=		audit_dtrace.c	\
		vnode_if.h

CFLAGS+=	-I${SYSDIR}/cddl/compat/opensolaris \
		-I${SYSDIR}/cddl/contrib/opensolaris/uts/common \
		-I${SYSDIR}

.include <bsd.kmod.mk>

CFLAGS+=	-include ${SYSDIR}/cddl/compat/opensolaris/sys/debug_compat.h
