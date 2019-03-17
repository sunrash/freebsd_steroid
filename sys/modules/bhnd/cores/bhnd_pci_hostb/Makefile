# $FreeBSD: releng/12.0/sys/modules/bhnd/cores/bhnd_pci_hostb/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH: ${SRCTOP}/sys/dev/bhnd/cores/pci
.PATH: ${SRCTOP}/sys/dev/bhnd/cores/pcie2

KMOD=	bhnd_pci_hostb
SRCS=	bhnd_pci_hostb.c bhnd_pcie2_hostb.c
SRCS+=	device_if.h bus_if.h pci_if.h \
	bhnd_bus_if.h bhnd_chipc_if.h

.include <bsd.kmod.mk>
