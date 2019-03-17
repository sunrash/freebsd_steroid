# $FreeBSD: releng/12.0/sys/modules/firewire/fwip/Makefile 314651 2017-03-04 10:10:17Z ngie $

# Makefile for the fwip(4) module (IP over IEEE1394)

.PATH: ${SRCTOP}/sys/dev/firewire ${SRCTOP}/sys/net

KMOD    = if_fwip
SRCS    = bus_if.h device_if.h \
          opt_inet.h opt_inet6.h opt_ofed.h \
          if_fwip.c if_fwipvar.h \
          firewire.h firewirereg.h \
          if_fwsubr.c

#CFLAGS += -DDEVICE_POLLING

.include <bsd.kmod.mk>
