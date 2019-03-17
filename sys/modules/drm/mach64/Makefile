# $FreeBSD: releng/12.0/sys/modules/drm/mach64/Makefile 338285 2018-08-24 00:02:00Z imp $

.PATH:	${SRCTOP}/sys/dev/drm
KMOD	= mach64
SRCS	= mach64_dma.c mach64_drv.c mach64_irq.c mach64_state.c
SRCS	+=device_if.h bus_if.h pci_if.h opt_drm.h

.include <bsd.kmod.mk>
