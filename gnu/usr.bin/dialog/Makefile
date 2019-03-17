# $FreeBSD: releng/12.0/gnu/usr.bin/dialog/Makefile 315175 2017-03-12 18:59:16Z imp $

DIALOG=	${SRCTOP}/contrib/dialog
PROG=   dialog

LIBADD=	dialog ncursesw m
CFLAGS+= -I${.CURDIR} -I${DIALOG}
.PATH:	${DIALOG}

WARNS?= 6

.include <bsd.prog.mk>
