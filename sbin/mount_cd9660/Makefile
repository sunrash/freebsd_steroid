#	@(#)Makefile	8.3 (Berkeley) 3/27/94
# $FreeBSD: releng/12.0/sbin/mount_cd9660/Makefile 314656 2017-03-04 11:33:01Z ngie $

PACKAGE=runtime
PROG=	mount_cd9660
SRCS=	mount_cd9660.c getmntopts.c
MAN=	mount_cd9660.8
LIBADD=	kiconv

MOUNT=	${.CURDIR:H}/mount
CFLAGS+= -I${MOUNT}

# Needs to be dynamically linked for optional dlopen() access to
# userland libiconv
NO_SHARED?=	NO

.PATH:	${MOUNT}

.include <bsd.prog.mk>
