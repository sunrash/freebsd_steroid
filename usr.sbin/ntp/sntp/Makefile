# $FreeBSD: releng/12.0/usr.sbin/ntp/sntp/Makefile 317388 2017-04-24 21:55:59Z brooks $

.include <src.opts.mk>

.PATH:	${SRCTOP}/contrib/ntp/sntp

PROG=	sntp
MAN=
SRCS= 	crypto.c kod_management.c log.c main.c networking.c \
	sntp-opts.c sntp.c utilities.c

CFLAGS+= -I${SRCTOP}/contrib/ntp/include \
	-I${SRCTOP}/contrib/ntp/include \
	-I${SRCTOP}/contrib/ntp/lib/isc/include \
	-I${SRCTOP}/contrib/ntp/lib/isc/unix/include \
	-I${SRCTOP}/contrib/ntp/lib/isc/pthreads/include \
	-I${SRCTOP}/contrib/ntp/sntp \
	-I${SRCTOP}/contrib/ntp/sntp/libopts \
	-I${SRCTOP}/contrib/ntp/sntp/libevent/include \
	-I${.CURDIR:H}/libntpevent \
	-I${.CURDIR:H}

LIBADD=	m opts ntp ntpevent pthread

.if ${MK_OPENSSL} != "no"
LIBADD+=	crypto
.else
LIBADD+=	md
.endif

.include <bsd.prog.mk>
