# $FreeBSD: releng/12.0/lib/libpmc/pmu-events/Makefile 334244 2018-05-26 19:29:19Z mmacy $

PROG=	jevents
SRCS=	jevents.c jsmn.c json.c
CFLAGS+= -Wno-cast-qual
MAN=

build-tools: jevents

.include <bsd.prog.mk>
