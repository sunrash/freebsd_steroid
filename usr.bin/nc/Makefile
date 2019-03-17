# $FreeBSD: releng/12.0/usr.bin/nc/Makefile 315170 2017-03-12 18:58:44Z imp $

.PATH: ${SRCTOP}/contrib/netcat

PROG=	nc
SRCS=	netcat.c atomicio.c socks.c

CFLAGS+=-DIPSEC
LIBADD=	ipsec

WARNS?=	2

.include <bsd.prog.mk>
