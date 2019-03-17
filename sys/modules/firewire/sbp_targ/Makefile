# $FreeBSD: releng/12.0/sys/modules/firewire/sbp_targ/Makefile 314651 2017-03-04 10:10:17Z ngie $

# Makefile for the SBP-II Target mode

.PATH: ${SRCTOP}/sys/dev/firewire

KMOD	= sbp_targ
SRCS	= bus_if.h device_if.h \
	  opt_cam.h opt_scsi.h \
	  sbp_targ.c sbp.h \
	  firewire.h firewirereg.h \
	  iec13213.h

.include <bsd.kmod.mk>
