#	@(#)Makefile	8.1 (Berkeley) 5/31/93
# $FreeBSD: releng/12.0/usr.bin/factor/Makefile 315170 2017-03-12 18:58:44Z imp $

.include <src.opts.mk>

PROG=	factor
SRCS=	factor.c pr_tbl.c
CFLAGS+=-I${SRCTOP}/usr.bin/primes

.if ${MK_OPENSSL} != "no"
CFLAGS+=-DHAVE_OPENSSL
LIBADD+=crypto
.endif

MAN=	factor.6
MLINKS+=factor.6 primes.6
.PATH:	${SRCTOP}/usr.bin/primes

.include <bsd.prog.mk>
