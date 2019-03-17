# $FreeBSD: releng/12.0/usr.bin/clang/llvm-objdump/Makefile 314564 2017-03-02 20:49:40Z dim $

PROG_CXX=	llvm-objdump
MAN=

SRCDIR=		tools/llvm-objdump
SRCS+=		COFFDump.cpp
SRCS+=		ELFDump.cpp
SRCS+=		MachODump.cpp
SRCS+=		WasmDump.cpp
SRCS+=		llvm-objdump.cpp

LIBADD+=	z

.include "../llvm.prog.mk"
