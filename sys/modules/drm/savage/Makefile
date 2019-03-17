# $FreeBSD: releng/12.0/sys/modules/drm/savage/Makefile 338285 2018-08-24 00:02:00Z imp $

.PATH:	${SRCTOP}/sys/dev/drm
KMOD= 	savage
CFLAGS += -I${SRCTOP}/sys/dev/drm
SRCS=	savage_bci.c savage_drv.c savage_state.c
SRCS+=	device_if.h bus_if.h pci_if.h opt_drm.h

.include <bsd.kmod.mk>
