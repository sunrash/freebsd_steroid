# $FreeBSD: releng/12.0/sys/modules/bce/Makefile 314651 2017-03-04 10:10:17Z ngie $
.PATH:	${SRCTOP}/sys/dev/bce
KMOD=	if_bce
SRCS=	opt_bce.h if_bce.c miibus_if.h miidevs.h device_if.h bus_if.h pci_if.h

#CFLAGS += -DBCE_DEBUG=0

.include <bsd.kmod.mk>
