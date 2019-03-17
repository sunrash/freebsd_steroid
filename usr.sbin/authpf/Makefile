# $FreeBSD: releng/12.0/usr.sbin/authpf/Makefile 314659 2017-03-04 11:38:03Z ngie $

.PATH:	${SRCTOP}/contrib/pf/authpf

PROG=	authpf
MAN=	authpf.8
BINOWN=	root
BINGRP= authpf
BINMODE= 6555

SRCS=   authpf.c

# XXX ALTQ:
CFLAGS+= -DENABLE_ALTQ

LIBADD=	m util

WARNS?=	3

LINKS=	${BINDIR}/authpf ${BINDIR}/authpf-noip
MLINKS=	authpf.8 authpf-noip.8

.include <bsd.prog.mk>
