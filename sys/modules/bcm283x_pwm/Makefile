# $FreeBSD: releng/12.0/sys/modules/bcm283x_pwm/Makefile 328223 2018-01-21 21:27:41Z phk $

.PATH: ${SRCTOP}/sys/arm/broadcom/bcm2835/

KMOD=	bcm283x_pwm
SRCS=	bcm2835_pwm.c

SRCS+= bus_if.h device_if.h ofw_bus_if.h

.include <bsd.kmod.mk>
