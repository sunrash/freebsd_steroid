# $FreeBSD: releng/12.0/sys/modules/bios/smapi/Makefile 314651 2017-03-04 10:10:17Z ngie $
#

.PATH:  ${SRCTOP}/sys/i386/bios

KMOD=	smapi
SRCS=	smapi.c smapi_bios.S \
	bus_if.h device_if.h

.include <bsd.kmod.mk>

CFLAGS.smapi_bios.S=	${CLANG_NO_IAS34}
