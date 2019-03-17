
# $FreeBSD: releng/12.0/sys/modules/aic7xxx/ahc/ahc_isa/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH:	${SRCTOP}/sys/dev/aic7xxx
KMOD=		ahc_isa

SRCS=	ahc_isa.c
SRCS+=	device_if.h bus_if.h pci_if.h isa_if.h
SRCS+=	opt_scsi.h opt_cam.h opt_aic7xxx.h

CFLAGS+=	-I${SRCTOP}/sys/dev/aic7xxx -I..

.include <bsd.kmod.mk>
