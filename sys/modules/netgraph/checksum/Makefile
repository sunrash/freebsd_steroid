# $FreeBSD: releng/12.0/sys/modules/netgraph/checksum/Makefile 331100 2018-03-17 17:18:37Z imp $

SYSDIR?=${SRCTOP}/sys
.include "${SYSDIR}/conf/kern.opts.mk"

KMOD=	ng_checksum
SRCS= 	ng_checksum.c opt_inet.h opt_inet6.h

.include <bsd.kmod.mk>
