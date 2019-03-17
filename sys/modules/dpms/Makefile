# $FreeBSD: releng/12.0/sys/modules/dpms/Makefile 314651 2017-03-04 10:10:17Z ngie $

KMOD=	dpms
SRCS=	bus_if.h device_if.h pci_if.h

.PATH:	${SRCTOP}/sys/dev/dpms
SRCS+=	dpms.c

.include <bsd.kmod.mk>
