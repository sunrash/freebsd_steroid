# $FreeBSD: releng/12.0/sbin/ipfw/Makefile 335921 2018-07-03 23:47:20Z jamie $

.include <src.opts.mk>

PACKAGE=ipfw
PROG=	ipfw
SRCS=	ipfw2.c dummynet.c ipv6.c main.c nat.c tables.c
SRCS+=	nat64lsn.c nat64stl.c nptv6.c
WARNS?=	2

.if ${MK_PF} != "no"
SRCS+=	altq.c
CFLAGS+=-DPF
.endif

LIBADD=	jail util
MAN=	ipfw.8

.include <bsd.prog.mk>
