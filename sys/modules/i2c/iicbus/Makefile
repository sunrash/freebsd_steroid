# $FreeBSD: releng/12.0/sys/modules/i2c/iicbus/Makefile 331868 2018-04-01 18:22:24Z ian $

.PATH:	${SRCTOP}/sys/dev/iicbus

KMOD=	iicbus
SRCS=	\
	bus_if.h \
	device_if.h \
	iic_recover_bus.c \
	iicbus.c \
	iicbus.h \
	iicbus_if.c \
	iicbus_if.h \
	iiconf.c \
	iiconf.h \
	opt_platform.h \

.if !empty(OPT_FDT)
SRCS+=	ofw_iicbus.c ofw_bus_if.h
.endif

.include <bsd.kmod.mk>
