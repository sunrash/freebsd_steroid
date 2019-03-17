#$FreeBSD: releng/12.0/sys/modules/i2c/controllers/ichsmb/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH:		${SRCTOP}/sys/dev/ichsmb
KMOD		= ichsmb
SRCS		= device_if.h bus_if.h iicbb_if.h pci_if.h smbus_if.h \
		  ichsmb.c ichsmb_pci.c ichsmb_reg.h ichsmb_var.h

.include <bsd.kmod.mk>
