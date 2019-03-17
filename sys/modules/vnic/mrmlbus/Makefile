# $FreeBSD: releng/12.0/sys/modules/vnic/mrmlbus/Makefile 314651 2017-03-04 10:10:17Z ngie $

SYSDIR?=${SRCTOP}/sys
.include "${SYSDIR}/conf/kern.opts.mk"

S=	${SRCTOP}/sys

.PATH: $S/dev/vnic

KMOD=	mrmlbus
SRCS=	device_if.h bus_if.h opt_platform.h pci_if.h ofw_bus_if.h miibus_if.h lmac_if.h
SRCS+=	mrml_bridge.c

CFLAGS+=	-DFDT

.include <bsd.kmod.mk>
