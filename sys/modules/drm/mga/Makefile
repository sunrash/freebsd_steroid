# $FreeBSD: releng/12.0/sys/modules/drm/mga/Makefile 338285 2018-08-24 00:02:00Z imp $

.PATH:	${SRCTOP}/sys/dev/drm
KMOD	= mga
SRCS	= mga_drv.c mga_state.c mga_warp.c mga_dma.c \
	mga_irq.c
SRCS	+=device_if.h bus_if.h pci_if.h opt_drm.h

.include <bsd.kmod.mk>
