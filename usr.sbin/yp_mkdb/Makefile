# $FreeBSD: releng/12.0/usr.sbin/yp_mkdb/Makefile 314453 2017-03-01 04:02:36Z ngie $

.PATH: ${SRCTOP}/libexec/ypxfr ${SRCTOP}/usr.sbin/ypserv

PROG=	yp_mkdb
MAN=	yp_mkdb.8
SRCS=	yp_mkdb.c yp_dblookup.c yp_dbwrite.c

CFLAGS+= -Dyp_error=warnx
CFLAGS+= -I${SRCTOP}/libexec/ypxfr -I${SRCTOP}/usr.sbin/ypserv

WARNS?=	1

.include <bsd.prog.mk>
