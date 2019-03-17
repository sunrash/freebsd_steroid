# $FreeBSD: releng/12.0/tools/tools/npe/npestats/Makefile 283002 2015-05-16 06:18:39Z adrian $

PROG=	npestats
SRCS=	main.c npestats.c
BINDIR=	/usr/local/bin
MAN=
LIBADD=	bsdstat
CFLAGS+=-I${.CURDIR}/../../../../lib/libbsdstat/

.include <bsd.prog.mk>
