# $FreeBSD: releng/12.0/sbin/ggate/ggatec/Makefile 314656 2017-03-04 11:33:01Z ngie $

.PATH: ${.CURDIR:H}/shared

PROG=	ggatec
MAN=	ggatec.8
SRCS=	ggatec.c ggate.c

CFLAGS+= -DMAX_SEND_SIZE=32768
CFLAGS+= -DLIBGEOM
CFLAGS+= -I${.CURDIR:H}/shared

LIBADD=	geom util pthread

.include <bsd.prog.mk>
