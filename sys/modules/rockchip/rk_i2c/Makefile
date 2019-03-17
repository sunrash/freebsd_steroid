# $FreeBSD: releng/12.0/sys/modules/rockchip/rk_i2c/Makefile 335115 2018-06-14 06:40:59Z manu $

.PATH: ${SRCTOP}/sys/arm64/rockchip

KMOD=	rk_i2c
SRCS=	rk_i2c.c

SRCS+=	\
	bus_if.h \
	clknode_if.h \
	device_if.h \
	iicbus_if.h \
	ofw_bus_if.h \
	opt_platform.h \

.include <bsd.kmod.mk>
