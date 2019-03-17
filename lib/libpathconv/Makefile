# $FreeBSD: releng/12.0/lib/libpathconv/Makefile 325247 2017-10-31 19:52:30Z bdrewery $

.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=		pathconv
SHLIB_MAJOR=	1
MAN=		rel2abs.3 abs2rel.3
INCS=		pathconv.h
SRCS=		abs2rel.c rel2abs.c


#VERSION_DEF=	${SRCTOP/lib/libc/Versions.def
#SYMBOL_MAPS=	${.CURDIR}/Symbol.map

HAS_TESTS=
#SUBDIR.${MK_TESTS}+= tests

.include <bsd.lib.mk>
