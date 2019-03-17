# $FreeBSD: releng/12.0/stand/i386/kgzldr/Makefile 336261 2018-07-13 20:08:18Z imp $

.include <bsd.init.mk>

PROG=	kgzldr.o
STRIP=
BINMODE=${LIBMODE}
BINDIR=	${LIBDIR}

SRCS=	start.s boot.c subr_inflate.c lib.c crt.s sio.s
CFLAGS=	-Os
CFLAGS+=-DKZIP
NO_SHARED=
LDFLAGS+=-Wl,-r
.PATH:	${SYSDIR}/kern

BOOT_COMCONSOLE_PORT?=	0x3f8
AFLAGS+=--defsym SIO_PRT=${BOOT_COMCONSOLE_PORT}

.include <bsd.prog.mk>
