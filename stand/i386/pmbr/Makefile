# $FreeBSD: releng/12.0/stand/i386/pmbr/Makefile 328769 2018-02-02 06:32:26Z imp $

PROG=	pmbr
STRIP=
BINMODE=${NOBINMODE}
SRCS=	${PROG}.s

ORG=	0x600

AFLAGS+=--defsym FLAGS=${BOOT_MBR_FLAGS}
LDFLAGS+=${LDFLAGS_BIN}

.include <bsd.prog.mk>
