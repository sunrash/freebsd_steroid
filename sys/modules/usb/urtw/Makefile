# $FreeBSD: releng/12.0/sys/modules/usb/urtw/Makefile 330749 2018-03-10 23:16:24Z avos $

.PATH: ${SRCTOP}/sys/dev/usb/wlan

KMOD    = if_urtw
SRCS    = if_urtw.c if_urtwreg.h if_urtwvar.h	\
	  bus_if.h device_if.h \
	  opt_bus.h opt_usb.h opt_wlan.h usb_if.h usbdevs.h

.include <bsd.kmod.mk>
