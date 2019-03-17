# $FreeBSD: releng/12.0/sys/modules/evdev/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH: ${SRCTOP}/sys/dev/evdev

KMOD=	evdev
SRCS=	cdev.c evdev.c evdev_mt.c evdev_utils.c
SRCS+=	opt_evdev.h bus_if.h device_if.h

.include <bsd.kmod.mk>
