#	from: @(#)Makefile	8.1 (Berkeley) 6/4/93
# $FreeBSD: releng/12.0/libexec/getty/Makefile 338471 2018-09-05 15:25:23Z brd $

CONFS=	gettytab
PROG=	getty
SRCS=	main.c init.c subr.c chat.c
LIBADD=	util
MAN=	gettytab.5 ttys.5 getty.8

WARNS?=	6
WFORMAT=0

.include <bsd.prog.mk>

