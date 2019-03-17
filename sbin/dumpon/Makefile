# $FreeBSD: releng/12.0/sbin/dumpon/Makefile 309818 2016-12-10 16:20:39Z def $

.include <src.opts.mk>

PACKAGE=runtime
PROG=	dumpon

.if ${MK_OPENSSL} != "no"
LIBADD=	crypto
CFLAGS+=-DHAVE_CRYPTO
.endif

MAN=	dumpon.8

.include <bsd.prog.mk>
