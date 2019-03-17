# $FreeBSD: releng/12.0/usr.bin/tail/Makefile 322515 2017-08-14 19:21:37Z ngie $
#	@(#)Makefile	8.1 (Berkeley) 6/6/93

.include <src.opts.mk>

PROG=	tail
SRCS=	forward.c misc.c read.c reverse.c tail.c

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>
