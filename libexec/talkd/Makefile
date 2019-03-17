#	@(#)Makefile	8.1 (Berkeley) 6/4/93
# $FreeBSD: releng/12.0/libexec/talkd/Makefile 314653 2017-03-04 11:28:03Z ngie $

PROG=	ntalkd
SRCS=	talkd.c announce.c process.c table.c print.c ttymsg.c
.PATH:  ${SRCTOP}/usr.bin/wall
MAN=	talkd.8
CFLAGS+=-I${SRCTOP}/usr.bin/wall

.include <bsd.prog.mk>
