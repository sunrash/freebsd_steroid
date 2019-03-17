#	@(#)Makefile	8.1 (Berkeley) 5/31/93
# $FreeBSD: releng/12.0/bin/rm/Makefile 338620 2018-09-12 19:41:16Z emaste $

.include <src.opts.mk>

PACKAGE=runtime
PROG=	rm

LINKS=	${BINDIR}/rm ${BINDIR}/unlink
MLINKS=	rm.1 unlink.1

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>
