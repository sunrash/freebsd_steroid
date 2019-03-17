# $FreeBSD: releng/12.0/sys/modules/glxiic/Makefile 314651 2017-03-04 10:10:17Z ngie $

#CFLAGS+=	-DGLXIIC_DEBUG

.PATH:	${SRCTOP}/sys/dev/glxiic
KMOD=	glxiic
SRCS=	glxiic.c
SRCS+=	device_if.h bus_if.h pci_if.h iicbus_if.h

.include <bsd.kmod.mk>
