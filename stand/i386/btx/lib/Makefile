# $FreeBSD: releng/12.0/stand/i386/btx/lib/Makefile 328769 2018-02-02 06:32:26Z imp $

.include <bsd.init.mk>

PROG=	crt0.o
INTERNALPROG=
SRCS=	btxcsu.S btxsys.s btxv86.s
CFLAGS+=-I${BOOTSRC}/i386/common
LDFLAGS+=-Wl,-r

.include <bsd.prog.mk>
