# $FreeBSD: releng/12.0/sys/modules/ucycom/Makefile 336052 2018-07-06 22:07:26Z ian $

S=	${SRCTOP}/sys
.PATH: $S/dev/usb/serial

KMOD=	ucycom
SRCS=	ucycom.c opt_usb.h device_if.h bus_if.h usbdevs.h

.include <bsd.kmod.mk>
