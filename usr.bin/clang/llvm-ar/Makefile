# $FreeBSD: releng/12.0/usr.bin/clang/llvm-ar/Makefile 311565 2017-01-06 23:05:29Z dim $

PROG_CXX=	llvm-ar

SRCDIR=		tools/llvm-ar
SRCS+=		llvm-ar.cpp

LIBADD+=	z

LINKS+=		${BINDIR}/llvm-ar ${BINDIR}/llvm-ranlib

.include "../llvm.prog.mk"
