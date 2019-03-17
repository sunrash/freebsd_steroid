#	@(#)Makefile	8.4 (Berkeley) 6/22/95
#
# $FreeBSD: releng/12.0/sbin/umount/Makefile 314656 2017-03-04 11:33:01Z ngie $

PACKAGE=runtime
PROG=	umount
SRCS=	umount.c vfslist.c mounttab.c
MAN=	umount.8

MOUNT=	${.CURDIR:H}/mount
UMNTALL= ${SRCTOP}/usr.sbin/rpc.umntall
CFLAGS+= -I${MOUNT} -I${UMNTALL}

.PATH: ${MOUNT} ${UMNTALL}

.include <bsd.prog.mk>
