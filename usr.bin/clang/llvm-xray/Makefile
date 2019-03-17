# $FreeBSD: releng/12.0/usr.bin/clang/llvm-xray/Makefile 321369 2017-07-22 11:08:25Z dim $

PROG_CXX=	llvm-xray
MAN=

SRCDIR=		tools/llvm-xray
SRCS+=		func-id-helper.cc
SRCS+=		llvm-xray.cc
SRCS+=		xray-extract.cc
SRCS+=		xray-registry.cc

LIBADD+=	z

.include "../llvm.prog.mk"
