# $FreeBSD: releng/12.0/sys/modules/allwinner/aw_spi/Makefile 333709 2018-05-17 10:25:01Z manu $

.PATH: ${SRCTOP}/sys/arm/allwinner

KMOD=	aw_spi
SRCS=	aw_spi.c

SRCS+=	\
	bus_if.h \
	clknode_if.h \
	device_if.h \
	ofw_bus_if.h \
	spibus_if.h \

.include <bsd.kmod.mk>
