# $FreeBSD: releng/12.0/lib/libsbuf/Makefile 322515 2017-08-14 19:21:37Z ngie $

PACKAGE=lib${LIB}
LIB=		sbuf
SHLIBDIR?= 	/lib
SRCS=		subr_prf.c subr_sbuf.c

SHLIB_MAJOR	= 6

SYMBOL_MAPS=    ${.CURDIR}/Symbol.map
VERSION_DEF=	${.CURDIR}/Version.def

.include <src.opts.mk>

.PATH:	${SRCTOP}/sys/kern

HAS_TESTS=
SUBDIR.${MK_TESTS}+=	tests

.include <bsd.lib.mk>
