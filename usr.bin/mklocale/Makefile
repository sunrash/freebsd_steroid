#	@(#)Makefile	8.1 (Berkeley) 6/7/93
# $FreeBSD: releng/12.0/usr.bin/mklocale/Makefile 315170 2017-03-12 18:58:44Z imp $

PROG=	mklocale
SRCS=	yacc.y lex.l y.tab.h
CFLAGS+= -I. -I${.CURDIR} -I${SRCTOP}/lib/libc/locale

NO_WMISSING_VARIABLE_DECLARATIONS=

.include <bsd.prog.mk>
