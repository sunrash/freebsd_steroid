# $FreeBSD: releng/12.0/sys/modules/acpi/aibs/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH:	${SRCTOP}/sys/dev/acpi_support

KMOD=	aibs
SRCS=	atk0110.c
SRCS+=	opt_acpi.h acpi_if.h bus_if.h device_if.h
SRCS+=	opt_ddb.h

.include <bsd.kmod.mk>
