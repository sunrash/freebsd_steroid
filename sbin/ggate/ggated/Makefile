# $FreeBSD: releng/12.0/sbin/ggate/ggated/Makefile 314656 2017-03-04 11:33:01Z ngie $

.PATH: ${.CURDIR:H}/shared

PROG=	ggated
MAN=	ggated.8
SRCS=	ggated.c ggate.c

LIBADD=	pthread util

CFLAGS+= -I${.CURDIR:H}/shared

.include <bsd.prog.mk>
