# $FreeBSD: releng/12.0/sys/modules/nand/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH: ${SRCTOP}/sys/dev/nand

KMOD = nand
SRCS=	nand.c nand_bbt.c nand_cdev.c nand_generic.c nand_geom.c \
	nand_id.c nandbus.c nandbus_if.c nand_if.c nfc_if.c \
	nand_if.h device_if.h bus_if.h nfc_if.h nandbus_if.h

.include <bsd.kmod.mk>
