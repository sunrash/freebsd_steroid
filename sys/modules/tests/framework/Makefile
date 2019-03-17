#
# $FreeBSD: releng/12.0/sys/modules/tests/framework/Makefile 314651 2017-03-04 10:10:17Z ngie $
#

.PATH: ${SRCTOP}/sys/tests/framework

KMOD=	kern_testfrwk
SRCS=	kern_testfrwk.c
SRCS+=	bus_if.h device_if.h

#
# Enable full debugging
#
#CFLAGS += -g

.include <bsd.kmod.mk>
