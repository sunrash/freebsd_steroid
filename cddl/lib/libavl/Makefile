# $FreeBSD: releng/12.0/cddl/lib/libavl/Makefile 314654 2017-03-04 11:30:04Z ngie $

.PATH: ${SRCTOP}/sys/cddl/contrib/opensolaris/common/avl

LIB=	avl
SRCS=	avl.c
WARNS?=	3
CFLAGS+= -I${SRCTOP}/sys/cddl/compat/opensolaris
CFLAGS+= -I${SRCTOP}/sys/cddl/contrib/opensolaris/uts/common

.include <bsd.lib.mk>
