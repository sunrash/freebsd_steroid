# $FreeBSD: releng/12.0/lib/libcxxrt/Makefile 312504 2017-01-20 04:53:00Z ngie $

PACKAGE=	clibs
SRCDIR=		${SRCTOP}/contrib/libcxxrt

SHLIB_MAJOR=	1
SHLIBDIR?=	/lib

.PATH: ${SRCDIR}

LIB=		cxxrt

SRCS+=		libelftc_dem_gnu3.c\
		terminate.cc\
		dynamic_cast.cc\
		memory.cc\
		auxhelper.cc\
		exception.cc\
		stdexcept.cc\
		typeinfo.cc\
		guard.cc

WARNS=		0
CFLAGS+=	-isystem ${SRCDIR} -nostdinc++
.if empty(CXXFLAGS:M-std=*)
CXXFLAGS+=	-std=c++11
.endif
VERSION_MAP=	${.CURDIR}/Version.map

.include <bsd.lib.mk>
