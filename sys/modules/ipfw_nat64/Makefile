# $FreeBSD: releng/12.0/sys/modules/ipfw_nat64/Makefile 333403 2018-05-09 11:59:24Z ae $

.PATH: ${SRCTOP}/sys/netpfil/ipfw/nat64

KMOD=	ipfw_nat64
SRCS=	ip_fw_nat64.c nat64_translate.c
SRCS+=	nat64lsn.c nat64lsn_control.c
SRCS+=	nat64stl.c nat64stl_control.c
SRCS+=	opt_ipfw.h

#CFLAGS+=	-DIPFIREWALL_NAT64_DIRECT_OUTPUT

.include <bsd.kmod.mk>
