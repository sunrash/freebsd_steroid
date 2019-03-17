# $FreeBSD: releng/12.0/sys/modules/acpi/acpi_asus_wmi/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH:	${SRCTOP}/sys/dev/acpi_support

KMOD=	acpi_asus_wmi
CFLAGS+=-I${SRCTOP}/sys/dev/acpi_support
SRCS=	acpi_asus_wmi.c opt_acpi.h acpi_if.h acpi_wmi_if.h device_if.h bus_if.h

.include <bsd.kmod.mk>
