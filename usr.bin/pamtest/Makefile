# $FreeBSD: releng/12.0/usr.bin/pamtest/Makefile 315170 2017-03-12 18:58:44Z imp $

OPENPAM=	${SRCTOP}/contrib/openpam
.PATH: ${OPENPAM}/include ${OPENPAM}/bin/pamtest

PROG= pamtest
SRCS= pamtest.c

LIBADD=	pam

.include <bsd.prog.mk>
