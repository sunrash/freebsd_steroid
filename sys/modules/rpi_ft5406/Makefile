# $FreeBSD: releng/12.0/sys/modules/rpi_ft5406/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH: ${SRCTOP}/sys/arm/broadcom/bcm2835/

KMOD=	rpi_ft5406
SRCS=	bcm2835_ft5406.c

SRCS+= bus_if.h device_if.h mbox_if.h ofw_bus_if.h

.include <bsd.kmod.mk>
