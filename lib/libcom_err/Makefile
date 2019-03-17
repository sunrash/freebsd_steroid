# $FreeBSD: releng/12.0/lib/libcom_err/Makefile 312501 2017-01-20 04:51:36Z ngie $

PACKAGE=lib${LIB}
LIB=	com_err
SRCS=	com_err.c error.c
INCS=	${COM_ERRDIR}/com_err.h ${COM_ERRDIR}/com_right.h
MAN=	com_err.3
COM_ERRDIR=	${SRCTOP}/contrib/com_err
CFLAGS+=	-I${COM_ERRDIR}

LDFLAGS=	-Wl,--no-undefined
VERSION_MAP=	${COM_ERRDIR}/version-script.map

.include <bsd.lib.mk>

.PATH:	${COM_ERRDIR}
