#	@(#)Makefile	8.1 (Berkeley) 6/6/93
# $FreeBSD: releng/12.0/usr.sbin/pwd_mkdb/Makefile 314659 2017-03-04 11:38:03Z ngie $

.PATH: ${SRCTOP}/lib/libc/gen		# for pw_scan.c

PROG=	pwd_mkdb
MAN=	pwd_mkdb.8
SRCS=	pw_scan.c pwd_mkdb.c

CFLAGS+= -I${SRCTOP}/lib/libc/gen		# for pw_scan.h

.include <bsd.prog.mk>
