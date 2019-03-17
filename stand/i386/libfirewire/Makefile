# $FreeBSD: releng/12.0/stand/i386/libfirewire/Makefile 328769 2018-02-02 06:32:26Z imp $

.include <bsd.init.mk>

LIB=		firewire

.PATH:		${SYSDIR}/dev/dcons ${SYSDIR}/dev/firewire
SRCS+=		firewire.c fwohci.c dconsole.c
SRCS+=		dcons.c fwcrom.c

CFLAGS+=	-D_BOOT

CFLAGS+=	-I${LDRSRC}
CFLAGS+=	-I${BOOTSRC}/i386/libi386

CFLAGS+=	-Wformat -Wall

.include <bsd.lib.mk>
