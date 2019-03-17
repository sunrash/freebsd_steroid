# $FreeBSD: releng/12.0/sys/modules/apm/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH: ${SRCTOP}/sys/i386/bios

KMOD=	apm
SRCS=	apm.c apm.h
SRCS+=	device_if.h bus_if.h

EXPORT_SYMS=	apm_display	\
		apm_softc

.include <bsd.kmod.mk>
