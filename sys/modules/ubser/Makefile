# $FreeBSD: releng/12.0/sys/modules/ubser/Makefile 314651 2017-03-04 10:10:17Z ngie $

S=	${SRCTOP}/sys
.PATH: $S/dev/usb/serial

KMOD=	ubser
SRCS=	ubser.c opt_usb.h device_if.h bus_if.h usbdevs.h

.include <bsd.kmod.mk>
