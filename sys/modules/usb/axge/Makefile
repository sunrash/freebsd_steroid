# $FreeBSD: releng/12.0/sys/modules/usb/axge/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH: ${SRCTOP}/sys/dev/usb/net

KMOD=	if_axge
SRCS+=	if_axge.c usbdevs.h
SRCS+=	bus_if.h device_if.h miibus_if.h usb_if.h \
	opt_bus.h opt_inet.h opt_usb.h

.include <bsd.kmod.mk>
