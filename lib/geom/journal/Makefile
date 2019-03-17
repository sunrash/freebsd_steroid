# $FreeBSD: releng/12.0/lib/geom/journal/Makefile 314656 2017-03-04 11:33:01Z ngie $

PACKAGE=runtime
.PATH: ${.CURDIR:H:H}/misc

GEOM_CLASS=	journal
SRCS+=	geom_journal_ufs.c

LIBADD=	ufs md

CFLAGS+=-I${SRCTOP}/sys

.include <bsd.lib.mk>
