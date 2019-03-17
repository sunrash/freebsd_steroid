# $FreeBSD: releng/12.0/sys/modules/vnic/vnicvf/Makefile 314651 2017-03-04 10:10:17Z ngie $

SYSDIR?=${SRCTOP}/sys
.include "${SYSDIR}/conf/kern.opts.mk"

S=	${SRCTOP}/sys

.PATH: $S/dev/vnic

KMOD=	vnicvf
SRCS=	nicvf_main.c nicvf_queues.c
SRCS+=	opt_platform.h ofw_bus_if.h lmac_if.h miibus_if.h pci_if.h bus_if.h device_if.h opt_inet.h opt_inet6.h

CFLAGS+=	-DFDT -DPCI_IOV

.include <bsd.kmod.mk>
