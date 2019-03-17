# $FreeBSD: releng/12.0/sys/modules/i2c/controllers/lpbb/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH:		${SRCTOP}/sys/dev/ppbus
KMOD		= lpbb
SRCS		= device_if.h bus_if.h iicbb_if.h ppbus_if.h \
		  lpbb.c

.include <bsd.kmod.mk>
