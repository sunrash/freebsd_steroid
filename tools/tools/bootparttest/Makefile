# $FreeBSD: releng/12.0/tools/tools/bootparttest/Makefile 325834 2017-11-14 23:02:19Z imp $

.PATH:		${SRCTOP}/stand/common

BINDIR?=	/usr/bin

PROG=		bootparttest
MAN=

SRCS=		bootparttest.c crc32.c stub.c part.c disk.c

CFLAGS=		-I${SRCTOP}/stand/common \
		-DLOADER_GPT_SUPPORT -DLOADER_MBR_SUPPORT -DPART_DEBUG \
		-DDISK_DEBUG

LIBADD+=	geom

.include <bsd.prog.mk>
