# $FreeBSD: releng/12.0/usr.sbin/lpr/chkprintcap/Makefile 314475 2017-03-01 05:14:45Z ngie $

.PATH: ${.CURDIR:H}/common_source

PROG=	chkprintcap
MAN=	chkprintcap.8
SRCS=	chkprintcap.c skimprintcap.c

CFLAGS+= -I${.CURDIR:H}/common_source

LIBADD=	lpr

.include <bsd.prog.mk>
