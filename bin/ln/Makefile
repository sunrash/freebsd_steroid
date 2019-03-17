#	@(#)Makefile	8.2 (Berkeley) 5/31/93
# $FreeBSD: releng/12.0/bin/ln/Makefile 322515 2017-08-14 19:21:37Z ngie $

.include <src.opts.mk>

PACKAGE=runtime
PROG=	ln
MAN=	ln.1 symlink.7

LINKS=	${BINDIR}/ln ${BINDIR}/link
MLINKS=	ln.1 link.1

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>
