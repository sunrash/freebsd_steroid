# $FreeBSD: releng/12.0/sys/modules/sound/driver/ich/Makefile 314651 2017-03-04 10:10:17Z ngie $

.PATH:		${SRCTOP}/sys/dev/sound/pci
KMOD		= snd_ich
SRCS		= device_if.h bus_if.h pci_if.h
SRCS		+= ich.c

.include <bsd.kmod.mk>
