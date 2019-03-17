# $FreeBSD: releng/12.0/sys/modules/ata/atapci/Makefile 314651 2017-03-04 10:10:17Z ngie $

SUBDIR += chipsets

.PATH: ${SRCTOP}/sys/dev/ata

KMOD=	atapci
SRCS=	ata-pci.c ata-dma.c ata-sata.c
SRCS+=	ata_if.h bus_if.h device_if.h pci_if.h

.include <bsd.kmod.mk>
