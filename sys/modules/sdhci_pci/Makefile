# $FreeBSD: releng/12.0/sys/modules/sdhci_pci/Makefile 327872 2018-01-12 12:14:14Z lwhsu $

.PATH: ${SRCTOP}/sys/dev/sdhci

KMOD=	sdhci_pci
SRCS=	sdhci_pci.c sdhci.h sdhci_if.h device_if.h bus_if.h pci_if.h mmcbr_if.h
SRCS+=	opt_mmccam.h

.include <bsd.kmod.mk>
