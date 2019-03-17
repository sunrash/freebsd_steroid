#	@(#)Makefile	8.1 (Berkeley) 6/6/93
# $FreeBSD: releng/12.0/usr.sbin/timed/timedc/Makefile 314659 2017-03-04 11:38:03Z ngie $

.PATH: ${.CURDIR:H}/timed

PROG=	timedc
MAN=	timedc.8
SRCS=	cmds.c cmdtab.c timedc.c byteorder.c measure.c cksum.c
BINOWN=	root
BINMODE= 4555

WARNS?=	1

.include "../../Makefile.inc"
.include <bsd.prog.mk>
