# $FreeBSD: releng/12.0/usr.sbin/apmd/Makefile 336743 2018-07-26 16:51:23Z brd $

CONFS=	apmd.conf
PROG=	apmd
MAN=	apmd.8
MANSUBDIR= /i386
SRCS=	apmd.c apmdlex.l apmdparse.y y.tab.h

PACKAGE=apm

WARNS?=	3

LIBADD=	l

CFLAGS+= -I${.CURDIR}

test:
	./apmd -d -f etc/apmd.conf -n

.include <bsd.prog.mk>
