# $FreeBSD: releng/12.0/usr.bin/opiepasswd/Makefile 315170 2017-03-12 18:58:44Z imp $
#
OPIE_DIST?=	${SRCTOP}/contrib/opie

PROG=	opiepasswd

CFLAGS+=-I${SRCTOP}/lib/libopie
CFLAGS+=-I${OPIE_DIST}
CFLAGS+=-DINSECURE_OVERRIDE

WARNS?=	0

LIBADD=	opie

BINOWN=	root
BINMODE=4555
PRECIOUSPROG=

.PATH:	${OPIE_DIST}

.include <bsd.prog.mk>
