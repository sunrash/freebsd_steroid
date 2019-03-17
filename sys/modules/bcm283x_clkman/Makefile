# $FreeBSD: releng/12.0/sys/modules/bcm283x_clkman/Makefile 328260 2018-01-22 08:33:59Z phk $

.PATH: ${SRCTOP}/sys/arm/broadcom/bcm2835/

KMOD=	bcm283x_clkman
SRCS=	bcm2835_clkman.c

EXPORT_SYMS=	bcm2835_clkman_set_frequency

SRCS+= bus_if.h device_if.h ofw_bus_if.h

.include <bsd.kmod.mk>
