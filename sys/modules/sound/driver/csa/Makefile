# $FreeBSD: releng/12.0/sys/modules/sound/driver/csa/Makefile 338424 2018-09-01 15:07:38Z gjb $

.PATH: ${SRCTOP}/sys/dev/sound/pci

KMOD=	snd_csa
SRCS=	device_if.h bus_if.h mpufoi_if.h pci_if.h
SRCS+=	csa.c csamidi.c csapcm.c

.include <bsd.kmod.mk>
