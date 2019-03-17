# $FreeBSD: releng/12.0/usr.sbin/cron/lib/Makefile 314659 2017-03-04 11:38:03Z ngie $

LIB=	cron
INTERNALLIB=
SRCS= entry.c env.c misc.c

WARNS?=	3

CFLAGS+= -I${.CURDIR:H}/cron
CFLAGS+= -DLOGIN_CAP -DPAM

.include <bsd.lib.mk>
