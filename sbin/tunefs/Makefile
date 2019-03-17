#	@(#)Makefile	8.1 (Berkeley) 6/5/93
# $FreeBSD: releng/12.0/sbin/tunefs/Makefile 310382 2016-12-22 00:35:12Z brooks $

PACKAGE=runtime
PROG=	tunefs
SRCS=	tunefs.c getmntopts.c
LIBADD=	ufs
MAN=	tunefs.8

MOUNT=	${SRCTOP}/sbin/mount
CFLAGS+=	-I${MOUNT}
.PATH:	${MOUNT}

WARNS=	3

.include <bsd.prog.mk>
