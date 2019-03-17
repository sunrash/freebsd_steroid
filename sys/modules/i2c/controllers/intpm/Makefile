# $FreeBSD: releng/12.0/sys/modules/i2c/controllers/intpm/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH:		${SRCTOP}/sys/dev/intpm
KMOD		= intpm
SRCS		= device_if.h bus_if.h iicbus_if.h smbus_if.h pci_if.h \
		  opt_intpm.h intpmreg.h intpm.c

.include <bsd.kmod.mk>
