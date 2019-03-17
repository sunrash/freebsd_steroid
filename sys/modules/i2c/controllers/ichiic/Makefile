#$FreeBSD: releng/12.0/sys/modules/i2c/controllers/ichiic/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH:		${SRCTOP}/sys/dev/ichiic
KMOD		= ig4
SRCS		= acpi_if.h device_if.h bus_if.h iicbus_if.h pci_if.h \
		  smbus_if.h ${ig4_acpi} ig4_iic.c ig4_pci.c ig4_reg.h \
		  ig4_var.h opt_acpi.h

.if ${MACHINE_CPUARCH} == "amd64" || ${MACHINE_CPUARCH} == "i386"
ig4_acpi=	ig4_acpi.c
.endif

.include <bsd.kmod.mk>
