#	$NetBSD: Makefile,v 1.2 2014/04/29 01:21:02 christos Exp $
#	$FreeBSD: releng/12.0/usr.bin/getaddrinfo/Makefile 317385 2017-04-24 21:31:27Z brooks $
.include <bsd.own.mk>

PROG=	getaddrinfo
SRCS=	getaddrinfo.c tables.h

CFLAGS+=	-I${SRCTOP}/lib/libnetbsd

LIBADD+=	netbsd util

SYS_SOCKET_H?=	${SRCTOP}/sys/sys/socket.h

CFLAGS+=	-I${.OBJDIR}
CLEANFILES+=	tables.h
tables.h: tables.awk ${SYS_SOCKET_H}
	LC_ALL=C awk -f ${.ALLSRC} > ${.TARGET}
.include <bsd.prog.mk>
