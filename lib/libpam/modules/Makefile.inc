# $FreeBSD: releng/12.0/lib/libpam/modules/Makefile.inc 312452 2017-01-20 03:27:47Z ngie $

PAMDIR=		${SRCTOP}/contrib/openpam

MK_INSTALLLIB=	no
MK_PROFILE=	no

CFLAGS+= -I${PAMDIR}/include -I${SRCTOP}/lib/libpam

SHLIB_NAME?=	${LIB}.so.${SHLIB_MAJOR}
LIBADD+=	pam

.include "../Makefile.inc"
