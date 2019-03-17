# $FreeBSD: releng/12.0/usr.sbin/efivar/Makefile 326472 2017-12-02 15:25:45Z imp $

PROG=	efivar
MAN=	efivar.8

LIBADD= efivar geom

SRCS=	efivar.c efiutil.c

EFIBOOT=${SRCTOP}/stand/efi
CFLAGS+=	-I${EFIBOOT}/include

.include <bsd.prog.mk>
