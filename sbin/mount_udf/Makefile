# $FreeBSD: releng/12.0/sbin/mount_udf/Makefile 314656 2017-03-04 11:33:01Z ngie $

PACKAGE=runtime
PROG=	mount_udf
SRCS=	mount_udf.c getmntopts.c
MAN=	mount_udf.8
LIBADD=	kiconv

MOUNT=	${.CURDIR:H}/mount
CFLAGS+= -I${MOUNT} -I${SRCTOP}/sys
.PATH:	${MOUNT}

# Needs to be dynamically linked for optional dlopen() access to
# userland libiconv
NO_SHARED?=	NO

.include <bsd.prog.mk>
