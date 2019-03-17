# $FreeBSD: releng/12.0/sys/modules/hyperv/pcib/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH:  ${SRCTOP}/sys/dev/hyperv/pcib \
	${SRCTOP}/sys/dev/hyperv/vmbus

KMOD=	vmbus_pcib
SRCS=	vmbus_pcib.c
SRCS+=	bus_if.h device_if.h pci_if.h pcib_if.h vmbus_if.h

CFLAGS+= -I${SRCTOP}/sys/dev/hyperv/pcib

.include <bsd.kmod.mk>
