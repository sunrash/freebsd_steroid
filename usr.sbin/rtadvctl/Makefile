# $FreeBSD: releng/12.0/usr.sbin/rtadvctl/Makefile 314659 2017-03-04 11:38:03Z ngie $
#
.PATH:	${.CURDIR:H}/rtadvd

PROG=	rtadvctl
MAN=	rtadvctl.8

SRCS=	rtadvctl.c control.c control_client.c if.c timer_subr.c

CFLAGS+= -I${.CURDIR} -I${.CURDIR:H}/rtadvd
WARNS?=	1

.include <bsd.prog.mk>
