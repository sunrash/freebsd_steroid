# $FreeBSD: releng/12.0/sys/modules/bge/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH: ${SRCTOP}/sys/dev/bge

KMOD=	if_bge
SRCS=	if_bge.c miibus_if.h miidevs.h device_if.h bus_if.h pci_if.h

.if ${MACHINE_CPUARCH} == sparc64
SRCS+=	ofw_bus_if.h
.endif

.include <bsd.kmod.mk>
