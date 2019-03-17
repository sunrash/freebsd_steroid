# $FreeBSD: releng/12.0/usr.sbin/fdcontrol/Makefile 314659 2017-03-04 11:38:03Z ngie $

.PATH: ${.CURDIR:H}/fdread

PROG=	fdcontrol
SRCS=	fdcontrol.c fdutil.c
CFLAGS+= -I${.CURDIR:H}/fdread
MAN=	fdcontrol.8

.include <bsd.prog.mk>
