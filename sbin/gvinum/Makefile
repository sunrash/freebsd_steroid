# $FreeBSD: releng/12.0/sbin/gvinum/Makefile 335273 2018-06-17 01:39:22Z eadler $

PACKAGE=runtime
PROG=	gvinum
SRCS=	gvinum.c gvinum.h geom_vinum_share.c
MAN=	gvinum.8

WARNS=		2
CFLAGS+=	-I${SRCTOP}/sys -I${SYSROOT:U${DESTDIR}}/${INCLUDEDIR}/edit

LIBADD=	edit geom

.PATH: ${SRCTOP}/sys/geom/vinum

.include <bsd.prog.mk>
