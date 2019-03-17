#
# $FreeBSD: releng/12.0/sys/modules/gpio/gpiokeys/Makefile 314651 2017-03-04 10:10:17Z ngie $
#

.PATH:	${SRCTOP}/sys/dev/gpio/

KMOD=	gpiokeys
SRCS=	gpiokeys.c gpiokeys_codes.c
SRCS+=	bus_if.h device_if.h gpio_if.h ofw_bus_if.h
SRCS+=	opt_platform.h opt_kbd.h

CFLAGS+=  -I. -I${SRCTOP}/sys/dev/gpio/

.include <bsd.kmod.mk>
