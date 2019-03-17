# $FreeBSD: releng/12.0/usr.sbin/ftp-proxy/Makefile 314659 2017-03-04 11:38:03Z ngie $

.PATH:	${SRCTOP}/contrib/pf/ftp-proxy

PROG=	ftp-proxy
MAN=	ftp-proxy.8

SRCS=	ftp-proxy.c filter.c

CFLAGS+=-I${SRCTOP}/contrib/pf/libevent

LIBADD=	event

WARNS?=	3

.include <bsd.prog.mk>
