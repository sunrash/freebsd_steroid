# $FreeBSD: releng/12.0/sys/modules/padlock_rng/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH: ${SRCTOP}/sys/dev/random

KMOD=	padlock_rng
SRCS=	nehemiah.c
SRCS+=	bus_if.h device_if.h

CFLAGS+= -I${SRCTOP}/sys

.include <bsd.kmod.mk>
