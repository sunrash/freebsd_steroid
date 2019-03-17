# $FreeBSD: releng/12.0/tools/tools/shlib-compat/test/Makefile.inc 275354 2014-12-01 08:14:25Z gleb $

LIB=		test${TESTNUM}
SHLIB_MAJOR=	0

SRCS+=		test.c

WARNS?=		3

DEBUG_FLAGS?=	-g

VERSION_DEF=	${.CURDIR}/../Versions.def
SYMBOL_MAPS=	${.CURDIR}/Symbol.map

MK_DEBUG_FILES=	yes
