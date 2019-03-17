#
# $FreeBSD: releng/12.0/sys/modules/usb/ugold/Makefile 314651 2017-03-04 10:10:17Z ngie $
#

S=     ${SRCTOP}/sys

.PATH: $S/dev/usb/misc

KMOD=	ugold
SRCS=	opt_bus.h opt_usb.h device_if.h bus_if.h usb_if.h vnode_if.h \
	usbdevs.h ugold.c

.include <bsd.kmod.mk>
