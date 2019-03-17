# $FreeBSD: releng/12.0/sys/modules/spigen/Makefile 336561 2018-07-20 17:46:55Z lwhsu $

.PATH:	${SRCTOP}/sys/dev/spibus
KMOD=	spigen
SRCS=	spigen.c

# Generated files...
SRCS+=	\
	bus_if.h \
	device_if.h \
	opt_platform.h \
	opt_spi.h \
	spibus_if.h \

.if !empty(OPT_FDT)
SRCS+=	ofw_bus_if.h
.endif

.include <bsd.kmod.mk>
