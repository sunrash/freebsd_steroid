# $FreeBSD: releng/12.0/lib/clang/clang.pre.mk 309124 2016-11-24 22:54:55Z dim $

.include "llvm.pre.mk"

CLANG_SRCS=	${LLVM_SRCS}/tools/clang

CLANG_TBLGEN?=	clang-tblgen
