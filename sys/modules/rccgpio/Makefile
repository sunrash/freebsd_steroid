# $FreeBSD: releng/12.0/sys/modules/rccgpio/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH:	${SRCTOP}/sys/dev/rccgpio
KMOD=	rccgpio
SRCS=	rccgpio.c
SRCS+=	device_if.h bus_if.h isa_if.h gpio_if.h opt_platform.h

.include <bsd.kmod.mk>
