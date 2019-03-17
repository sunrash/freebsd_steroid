# $FreeBSD: releng/12.0/usr.bin/iscsictl/Makefile 315170 2017-03-12 18:58:44Z imp $

PACKAGE=	iscsi
PROG=		iscsictl
SRCS=		iscsictl.c periphs.c parse.y token.l y.tab.h
CFLAGS+=	-I${.CURDIR}
CFLAGS+=	-I${SRCTOP}/sys/dev/iscsi
MAN=		iscsi.conf.5 iscsictl.8

LIBADD=		xo

YFLAGS+=	-v
LFLAGS+=	-i
CLEANFILES=	y.tab.c y.tab.h y.output

WARNS=		6
NO_WMISSING_VARIABLE_DECLARATIONS=

.include <bsd.prog.mk>
