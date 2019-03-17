# $FreeBSD: releng/12.0/sys/modules/sdhci_acpi/Makefile 327872 2018-01-12 12:14:14Z lwhsu $

.PATH: ${SRCTOP}/sys/dev/sdhci

KMOD=	sdhci_acpi
SRCS=	sdhci_acpi.c sdhci.h sdhci_if.h
SRCS+=	acpi_if.h device_if.h bus_if.h pci_if.h mmcbr_if.h
SRCS+=	opt_acpi.h opt_mmccam.h

.include <bsd.kmod.mk>
