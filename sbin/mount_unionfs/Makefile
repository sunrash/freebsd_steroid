#	@(#)Makefile	8.3 (Berkeley) 3/27/94
# $FreeBSD: releng/12.0/sbin/mount_unionfs/Makefile 314656 2017-03-04 11:33:01Z ngie $

PACKAGE=runtime
PROG=	mount_unionfs
SRCS=	mount_unionfs.c getmntopts.c
MAN=	mount_unionfs.8

MOUNT=	${.CURDIR:H}/mount
CFLAGS+=-I${MOUNT}

.PATH:	${MOUNT}

.include <bsd.prog.mk>
