#	@(#)Makefile	8.1 (Berkeley) 5/31/93
# $FreeBSD: releng/12.0/usr.bin/fortune/fortune/Makefile 314893 2017-03-08 05:31:54Z ngie $

PROG=	fortune
MAN=	fortune.6
CFLAGS+=-DDEBUG -I${FORTUNE_SRC}/strfile

.include <bsd.prog.mk>

test:	${PROG}
	./${PROG} -m brass
