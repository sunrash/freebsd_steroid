# ioat Loadable Kernel Module
#
# $FreeBSD: releng/12.0/sys/modules/ioat/Makefile 314651 2017-03-04 10:10:17Z ngie $

IOAT_SRC_PATH = ${SRCTOP}/sys

.PATH:  ${IOAT_SRC_PATH}/dev/ioat

KMOD=	ioat
SRCS=	ioat.c ioat_test.c
SRCS+=	device_if.h bus_if.h pci_if.h
SRCS+=	opt_ddb.h

CFLAGS+=	-I${IOAT_SRC_PATH}

.include <bsd.kmod.mk>
