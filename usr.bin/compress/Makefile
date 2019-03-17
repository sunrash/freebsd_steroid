#	@(#)Makefile	8.2 (Berkeley) 4/17/94
# $FreeBSD: releng/12.0/usr.bin/compress/Makefile 322515 2017-08-14 19:21:37Z ngie $

.include <src.opts.mk>

PROG=	compress
SRCS=	compress.c zopen.c
LINKS=	${BINDIR}/compress ${BINDIR}/uncompress
MLINKS=	compress.1 uncompress.1

# XXX zopen is not part of libc
# MAN=zopen.3

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>
