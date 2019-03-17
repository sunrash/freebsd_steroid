# $FreeBSD: releng/12.0/sys/modules/mly/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH: ${SRCTOP}/sys/dev/mly

KMOD=	mly
SRCS=	mly.c
SRCS+=	opt_scsi.h opt_cam.h
SRCS+=	device_if.h bus_if.h pci_if.h

#CFLAGS+=	-DMLY_DEBUG=1
CFLAGS+=	-DMLY_MODULE

.include <bsd.kmod.mk>
