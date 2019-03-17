# $FreeBSD: releng/12.0/sys/modules/bytgpio/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH:	${SRCTOP}/sys/dev/gpio
KMOD=	bytgpio
SRCS=	bytgpio.c
SRCS+=	acpi_if.h device_if.h bus_if.h gpio_if.h opt_acpi.h opt_platform.h

.include <bsd.kmod.mk>
