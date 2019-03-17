#	@(#)Makefile	8.1 (Berkeley) 6/6/93
# $FreeBSD: releng/12.0/usr.bin/vmstat/Makefile 335036 2018-06-13 08:52:04Z eadler $

.include <src.opts.mk>

PROG=	vmstat
MAN=	vmstat.8
LIBADD=	devstat kvm memstat xo util

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>
