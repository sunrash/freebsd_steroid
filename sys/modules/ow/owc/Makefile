# $FreeBSD: releng/12.0/sys/modules/ow/owc/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH: ${SRCTOP}/sys/dev/ow

KMOD=	owc
SRCS=	owc_gpiobus.c
SRCS+=	gpio_if.h gpiobus_if.h owll_if.h ofw_bus_if.h bus_if.h device_if.h
SRCS+=	opt_platform.h

.include <bsd.kmod.mk>
