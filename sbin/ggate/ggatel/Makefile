# $FreeBSD: releng/12.0/sbin/ggate/ggatel/Makefile 314656 2017-03-04 11:33:01Z ngie $

.PATH: ${.CURDIR:H}/shared

PROG=	ggatel
MAN=	ggatel.8
SRCS=	ggatel.c ggate.c

CFLAGS+= -DLIBGEOM
CFLAGS+= -I${.CURDIR:H}/shared

LIBADD=	geom util

.include <bsd.prog.mk>
