# $FreeBSD: releng/12.0/sys/modules/usb/udl/Makefile 314651 2017-03-04 10:10:17Z ngie $

S=     ${SRCTOP}/sys

.PATH: $S/dev/usb/video

KMOD=	udl
SRCS=	opt_bus.h opt_usb.h fb_if.h device_if.h \
	bus_if.h usb_if.h vnode_if.h usbdevs.h \
	udl.c

.include <bsd.kmod.mk>
