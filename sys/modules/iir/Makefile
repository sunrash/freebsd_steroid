# $FreeBSD: releng/12.0/sys/modules/iir/Makefile 314651 2017-03-04 10:10:17Z ngie $

KMOD		=  iir
.PATH:		${SRCTOP}/sys/dev/${KMOD}
SRCS		=  iir.c iir_ctrl.c iir_pci.c
SRCS		+= opt_scsi.h opt_cam.h
SRCS		+= device_if.h bus_if.h pci_if.h

.include <bsd.kmod.mk>
