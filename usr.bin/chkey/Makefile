# $FreeBSD: releng/12.0/usr.bin/chkey/Makefile 315170 2017-03-12 18:58:44Z imp $

.include <src.opts.mk>

.PATH: ${SRCTOP}/usr.bin/newkey

PROG=	chkey
SRCS=	chkey.c generic.c update.c
CFLAGS+= -I${SRCTOP}/usr.bin/newkey
.if ${MK_NIS} != "no"
CFLAGS+= -DYP
.endif
LIBADD+=	rpcsvc mp

.include <bsd.prog.mk>
