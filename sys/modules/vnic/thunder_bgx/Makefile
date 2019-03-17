# $FreeBSD: releng/12.0/sys/modules/vnic/thunder_bgx/Makefile 314651 2017-03-04 10:10:17Z ngie $

SYSDIR?=${SRCTOP}/sys
.include "${SYSDIR}/conf/kern.opts.mk"

S=	${SRCTOP}/sys

.PATH: $S/dev/vnic

KMOD=	thunder_bgx
SRCS=	thunder_bgx.c thunder_bgx_fdt.c
SRCS+=	opt_platform.h device_if.h bus_if.h pci_if.h lmac_if.h ofw_bus_if.h

CFLAGS+=	-DFDT

.include <bsd.kmod.mk>
