# $FreeBSD: releng/12.0/sys/modules/mdio/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH: ${SRCTOP}/sys/dev/mdio

KMOD=	mdio
SRCS=	mdio.c
SRCS+=	mdio_if.c mdio_if.h
SRCS+=	device_if.h bus_if.h

.include <bsd.kmod.mk>
