# $FreeBSD: releng/12.0/usr.bin/minigzip/Makefile 315170 2017-03-12 18:58:44Z imp $

SRCDIR=	${SRCTOP}/contrib/zlib/test
.PATH:	${SRCDIR}

PROG=	minigzip

WARNS?=	5
CFLAGS+=-DUSE_MMAP
LIBADD=	z

.include <bsd.prog.mk>
