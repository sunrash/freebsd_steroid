# $FreeBSD: releng/12.0/lib/libdl/Makefile 331743 2018-03-29 19:43:29Z kevans $

PACKAGE=clibs
LIB=dl
SHLIB_MAJOR=1

.PATH:	${SRCTOP}/lib/libc/gen
CFLAGS+=-I${SRCTOP}/lib/libc/include
CFLAGS+=-DIN_LIBDL
LDFLAGS+=-Wl,-F,libc.so.7
VERSION_DEF=${SRCTOP}/lib/libc/Versions.def
SYMBOL_MAPS=${.CURDIR}/Symbol.map

SRCS =	dlfcn.c

.include <bsd.lib.mk>
