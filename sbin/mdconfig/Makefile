# $FreeBSD: releng/12.0/sbin/mdconfig/Makefile 322515 2017-08-14 19:21:37Z ngie $

.include <src.opts.mk>

PACKAGE=runtime
PROG=		mdconfig
MAN=		mdconfig.8

LIBADD=		util geom

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>
