# $FreeBSD: releng/12.0/sbin/decryptcore/Makefile 314656 2017-03-04 11:33:01Z ngie $

PROG=	decryptcore

LIBADD=	crypto pjdlog

MAN=	decryptcore.8

CFLAGS+=-I${SRCTOP}/lib/libpjdlog

WARNS?=	6

.include <bsd.prog.mk>
