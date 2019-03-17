# $FreeBSD: releng/12.0/lib/libblocksruntime/Makefile 312459 2017-01-20 03:56:10Z ngie $

PACKAGE=lib${LIB:tl}
LIB=	BlocksRuntime
SHLIB_MAJOR=0
CFLAGS+=-I${.CURDIR}
WARNS?=	2

.PATH: ${SRCTOP}/contrib/compiler-rt/lib/BlocksRuntime

INCS=	Block.h Block_private.h
SRCS=	data.c runtime.c

.include <bsd.lib.mk>
