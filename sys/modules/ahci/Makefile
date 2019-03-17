# $FreeBSD: releng/12.0/sys/modules/ahci/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH: ${SRCTOP}/sys/dev/ahci

KMOD=	ahci
SRCS=	ahci.c ahci_pci.c ahciem.c ahci.h device_if.h bus_if.h pci_if.h opt_cam.h

.if ${MACHINE_CPUARCH} == "aarch64"
SRCS+=	ahci_generic.c acpi_if.h ofw_bus_if.h
.endif

.include <bsd.kmod.mk>
