# $FreeBSD: releng/12.0/tools/diag/prtblknos/Makefile 332798 2018-04-19 22:43:55Z mckusick $

BINDIR?=	/usr/bin

PROG=	prtblknos
MAN=

SRCS=	main.c prtblknos.c

LIBADD+=ufs

WARNS?=	3

test:	${PROG}
	./${PROG} > a

.include <bsd.prog.mk>
