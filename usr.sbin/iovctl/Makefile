# $FreeBSD: releng/12.0/usr.sbin/iovctl/Makefile 314659 2017-03-04 11:38:03Z ngie $

PROG=	iovctl
SRCS=	iovctl.c parse.c validate.c
LIBADD=	nv ucl m

CFLAGS+=-I${SRCTOP}/contrib/libucl/include

WARNS?=6

MAN=	\
	iovctl.8 \
	iovctl.conf.5 \

.include <bsd.own.mk>
.include <bsd.prog.mk>

