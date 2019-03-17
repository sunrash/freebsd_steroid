# $FreeBSD: releng/12.0/sys/modules/ciss/Makefile 314651 2017-03-04 10:10:17Z ngie $

KMOD		=  ciss
.PATH:		${SRCTOP}/sys/dev/${KMOD}
SRCS		=  ciss.c
SRCS		+= opt_scsi.h opt_cam.h
SRCS		+= device_if.h bus_if.h pci_if.h

#CFLAGS		+=-DCISS_DEBUG

.include <bsd.kmod.mk>
