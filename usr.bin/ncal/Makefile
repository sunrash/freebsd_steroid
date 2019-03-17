# $FreeBSD: releng/12.0/usr.bin/ncal/Makefile 322515 2017-08-14 19:21:37Z ngie $

.include <src.opts.mk>

PROG=	ncal

LIBADD=	calendar ncursesw

LINKS=	${BINDIR}/ncal ${BINDIR}/cal
MLINKS=	ncal.1 cal.1

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>
