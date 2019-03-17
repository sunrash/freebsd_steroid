# $FreeBSD: releng/12.0/usr.sbin/cron/crontab/Makefile 314659 2017-03-04 11:38:03Z ngie $

BINDIR=	/usr/bin

PROG=	crontab
MAN=	crontab.1 crontab.5
BINOWN=	root
BINMODE=4555
PRECIOUSPROG=

WARNS?=	3

CFLAGS+= -I${.CURDIR:H}/cron

LIBADD=	cron md util

.include <bsd.prog.mk>
