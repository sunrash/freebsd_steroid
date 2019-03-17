# $FreeBSD: releng/12.0/usr.sbin/bhyveload/Makefile 325834 2017-11-14 23:02:19Z imp $

PROG=	bhyveload
SRCS=	bhyveload.c
MAN=	bhyveload.8
PACKAGE=	bhyve

LIBADD=	vmmapi

WARNS?=	3

CFLAGS+=-I${SRCTOP}/stand/userboot

.include <bsd.prog.mk>
