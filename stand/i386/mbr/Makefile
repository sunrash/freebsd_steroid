# $FreeBSD: releng/12.0/stand/i386/mbr/Makefile 328769 2018-02-02 06:32:26Z imp $

PROG=	mbr
STRIP=
BINMODE=${NOBINMODE}
SRCS=	${PROG}.s

# MBR flags: 0x80 -- try packet interface (also known as EDD or LBA)
BOOT_MBR_FLAGS?=	0x80

ORG=	0x600

AFLAGS+=--defsym FLAGS=${BOOT_MBR_FLAGS}
LDFLAGS+=${LDFLAGS_BIN}

.include <bsd.prog.mk>
