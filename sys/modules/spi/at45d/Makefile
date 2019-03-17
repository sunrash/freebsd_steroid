# $FreeBSD: releng/12.0/sys/modules/spi/at45d/Makefile 331868 2018-04-01 18:22:24Z ian $

.PATH:	${SRCTOP}/sys/dev/flash

KMOD=	at45d
SRCS=	at45d.c

# Generated files...
SRCS+=	\
	bus_if.h \
	device_if.h \
	opt_platform.h \
	spibus_if.h \

.if !empty(OPT_FDT)
SRCS+=	ofw_bus_if.h
.endif

.include <bsd.kmod.mk>
