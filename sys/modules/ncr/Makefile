# $FreeBSD: releng/12.0/sys/modules/ncr/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH: ${SRCTOP}/sys/dev/ncr

KMOD=	ncr
SRCS=	ncr.c
SRCS+=	device_if.h bus_if.h pci_if.h opt_ncr.h opt_cam.h

.include <bsd.kmod.mk>
