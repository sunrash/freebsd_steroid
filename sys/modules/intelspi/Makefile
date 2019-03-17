# $FreeBSD: releng/12.0/sys/modules/intelspi/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH:	${SRCTOP}/sys/dev/intel
KMOD=	intelspi
SRCS=	spi.c
SRCS+=	acpi_if.h device_if.h bus_if.h opt_acpi.h spibus_if.h

.include <bsd.kmod.mk>
