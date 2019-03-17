# $FreeBSD: releng/12.0/sys/modules/aha/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH: ${SRCTOP}/sys/dev/aha

KMOD=	aha
SRCS=	aha.c aha_isa.c ahareg.h opt_cam.h device_if.h bus_if.h \
	isa_if.h

.include <bsd.kmod.mk>
