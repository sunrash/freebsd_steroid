#        @(#)Makefile	8.1 (Berkeley) 5/31/93
# $FreeBSD: releng/12.0/bin/test/Makefile 322515 2017-08-14 19:21:37Z ngie $

.include <src.opts.mk>

PACKAGE=runtime
PROG=	test
LINKS=	${BINDIR}/test ${BINDIR}/[
MLINKS=	test.1 [.1

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>
