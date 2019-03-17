# $FreeBSD: releng/12.0/sys/modules/bhnd/cores/bhnd_pci/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH: ${SRCTOP}/sys/dev/bhnd/cores/pci
.PATH: ${SRCTOP}/sys/dev/bhnd/cores/pcie2

KMOD=	bhnd_pci
SRCS=	bhnd_pci.c bhnd_pcie2.c
SRCS+=	device_if.h bus_if.h bhnd_bus_if.h

.include <bsd.kmod.mk>
