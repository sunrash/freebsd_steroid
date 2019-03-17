# $FreeBSD: releng/12.0/usr.sbin/kbdcontrol/Makefile 275054 2014-11-25 16:57:27Z bapt $

PROG=	kbdcontrol
MAN=	kbdcontrol.1 kbdmap.5
MLINKS= kbdmap.5 keymap.5
SRCS=	kbdcontrol.c lex.l

WARNS?=	4
CFLAGS+= -I${.CURDIR}

LIBADD=	l

.include <bsd.prog.mk>
