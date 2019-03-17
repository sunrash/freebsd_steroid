# $FreeBSD: releng/12.0/lib/libifconfig/Makefile 329853 2018-02-23 03:11:43Z asomers $

PACKAGE=	lib${LIB}
LIB=		ifconfig
PRIVATELIB=	true
# Don't build shared library, for now.
NO_PIC= 

SHLIBDIR?=	/lib
SHLIB_MAJOR=	1
SRCS=		libifconfig.c libifconfig_carp.c libifconfig_inet.c
SRCS+=		libifconfig_inet6.c libifconfig_internal.c libifconfig_lagg.c
SRCS+=		libifconfig_media.c

INCSDIR=	${INCLUDEDIR}
INCS=		libifconfig.h

#MAN=		libifconfig.3

CFLAGS+= -I${.CURDIR}
NO_WCAST_ALIGN= yes

.include <bsd.lib.mk>
