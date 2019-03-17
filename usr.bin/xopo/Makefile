# $FreeBSD: releng/12.0/usr.bin/xopo/Makefile 319999 2017-06-16 06:29:21Z phil $

.include <src.opts.mk>

LIBXOSRC=	${SRCTOP}/contrib/libxo

.PATH:
.PATH:	${LIBXOSRC}/xopo

PROG=	xopo
MAN=	xopo.1

# XXX For xoversion.h
CFLAGS+=-I${LIBXOSRC}/libxo

# XXX For xo_config.h
CFLAGS+=-I${SRCTOP}/lib/libxo

LIBADD=	xo util

.include <bsd.prog.mk>
