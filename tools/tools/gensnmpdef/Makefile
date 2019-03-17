# $FreeBSD: releng/12.0/tools/tools/gensnmpdef/Makefile 311748 2017-01-09 05:46:41Z ngie $

.PATH:	${SRCTOP}/contrib/bsnmp/gensnmpdef

PROG=	gensnmpdef

SRCS=	gensnmpdef.c

MAN=	gensnmpdef.1

LOCALBASE?=	/usr/local

BINDIR=	${LOCALBASE}/bin

MANDIR=	${LOCALBASE}/man/man

CFLAGS+=	-I${LOCALBASE}/include
LDFLAGS+=	-L${LOCALBASE}/lib

LDADD+=	-lsmi

WARNS?=	6

.include <bsd.prog.mk>
