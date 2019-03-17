# $FreeBSD: releng/12.0/usr.sbin/fwcontrol/Makefile 314659 2017-03-04 11:38:03Z ngie $

PROG=	fwcontrol
SRCS=	fwcontrol.c fwcrom.c fwdv.c fwmpegts.c
MAN=	fwcontrol.8
WARNS?=	3

.PATH:	${SRCTOP}/sys/dev/firewire

SDIR= ${SRCTOP}/sys
CFLAGS+=-I${.CURDIR} -I${SDIR}

.include <bsd.prog.mk>
