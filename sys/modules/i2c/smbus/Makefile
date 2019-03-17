# $FreeBSD: releng/12.0/sys/modules/i2c/smbus/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH:		${SRCTOP}/sys/dev/smbus
KMOD		= smbus
SRCS		= device_if.h bus_if.h smbus_if.h smbus_if.c \
		  smbconf.h smbconf.c smbus.h smbus.c

.include <bsd.kmod.mk>
