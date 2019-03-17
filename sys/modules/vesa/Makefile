# $FreeBSD: releng/12.0/sys/modules/vesa/Makefile 314651 2017-03-04 10:10:17Z ngie $

KMOD=	vesa
SRCS=	opt_vga.h opt_vesa.h
SRCS+=	bus_if.h device_if.h pci_if.h

.PATH:	${SRCTOP}/sys/dev/fb
SRCS+=	vesa.c

.PATH:	${SRCTOP}/sys/dev/syscons
SRCS+=	scvesactl.c

.include <bsd.kmod.mk>
