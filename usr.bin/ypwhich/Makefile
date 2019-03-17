#	from: @(#)Makefile	5.8 (Berkeley) 7/28/90
# $FreeBSD: releng/12.0/usr.bin/ypwhich/Makefile 315170 2017-03-12 18:58:44Z imp $

YPSERV=${SRCTOP}/usr.sbin/ypserv/common
.PATH: ${YPSERV}

PROG=	ypwhich
SRCS=	yplib_host.c ypwhich.c

CFLAGS+=	-I${YPSERV} -I.

WARNS?=	2

.include <bsd.prog.mk>
