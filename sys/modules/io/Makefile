# $FreeBSD: releng/12.0/sys/modules/io/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH: ${SRCTOP}/sys/dev/io
.PATH: ${SRCTOP}/sys/${MACHINE_CPUARCH}/${MACHINE_CPUARCH}

KMOD=	io
SRCS=	iodev.c io.c
SRCS+=	bus_if.h device_if.h

.include <bsd.kmod.mk>
