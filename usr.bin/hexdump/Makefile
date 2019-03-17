#	@(#)Makefile	8.1 (Berkeley) 6/6/93
# $FreeBSD: releng/12.0/usr.bin/hexdump/Makefile 322515 2017-08-14 19:21:37Z ngie $

.include <src.opts.mk>

PROG=	hexdump
SRCS=	conv.c display.c hexdump.c hexsyntax.c odsyntax.c parse.c
MAN=	hexdump.1 od.1
MLINKS=	hexdump.1 hd.1
LINKS=	${BINDIR}/hexdump ${BINDIR}/od
LINKS+=	${BINDIR}/hexdump ${BINDIR}/hd

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>
