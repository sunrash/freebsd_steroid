# $FreeBSD: releng/12.0/sys/modules/malo/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH: ${SRCTOP}/sys/dev/malo

KMOD    = if_malo
SRCS    = if_malo.c if_malohal.c if_malo_pci.c
SRCS+=	device_if.h bus_if.h pci_if.h opt_malo.h

opt_malo.h:
	echo '#define MALO_DEBUG 1'> $@

.include <bsd.kmod.mk>
