# $FreeBSD: releng/12.0/tools/tools/cxgbtool/Makefile 264400 2014-04-13 05:21:56Z imp $

PROG=	cxgbtool
SRCS=	cxgbtool.c
MAN=
CFLAGS+= -I${.CURDIR}/../../../sys/dev/cxgb -I.
CFLAGS+= -DCONFIG_T3_REGS -DCHELSIO_INTERNAL
BINDIR?= /usr/sbin

.include <bsd.prog.mk>
