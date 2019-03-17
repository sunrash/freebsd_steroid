# $FreeBSD: releng/12.0/sys/modules/veriexec/Makefile 335400 2018-06-20 00:48:46Z stevek $

.PATH: ${.PARSEDIR:H:H}/dev/veriexec

.include <bsd.own.mk>

KMOD=	veriexec
SRCS=	verified_exec.c
SRCS+=	bus_if.h device_if.h vnode_if.h

.include <bsd.kmod.mk>

