# $FreeBSD: releng/12.0/sys/modules/tsec/Makefile 314651 2017-03-04 10:10:17Z ngie $

SYSDIR?=${SRCTOP}/sys

.PATH:	${SYSDIR}/dev/tsec

KMOD=	if_tsec
SRCS=	if_tsec.c if_tsec_fdt.c
SRCS+=	bus_if.h device_if.h miibus_if.h miidevs.h ofw_bus_if.h

.include <bsd.kmod.mk>
