# $FreeBSD: releng/12.0/sys/modules/usb/uep/Makefile 337348 2018-08-05 11:14:13Z wulf $

S=     ${SRCTOP}/sys

.PATH: $S/dev/usb/input

KMOD=	uep
SRCS=	opt_bus.h opt_evdev.h opt_usb.h device_if.h bus_if.h usb_if.h \
	vnode_if.h usbdevs.h uep.c

.include <bsd.kmod.mk>
