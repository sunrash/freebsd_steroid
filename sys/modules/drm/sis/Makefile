# $FreeBSD: releng/12.0/sys/modules/drm/sis/Makefile 338285 2018-08-24 00:02:00Z imp $

.PATH:	${SRCTOP}/sys/dev/drm
KMOD= 	sis
SRCS=	sis_drv.c sis_ds.c sis_mm.c
SRCS+=	device_if.h bus_if.h pci_if.h opt_drm.h

.include <bsd.kmod.mk>
