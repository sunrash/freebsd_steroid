# $FreeBSD: releng/12.0/usr.bin/clang/opt/Makefile 309124 2016-11-24 22:54:55Z dim $

PROG_CXX=	opt

SRCDIR=		tools/opt
SRCS+=		AnalysisWrappers.cpp
SRCS+=		BreakpointPrinter.cpp
SRCS+=		GraphPrinters.cpp
SRCS+=		NewPMDriver.cpp
SRCS+=		PassPrinters.cpp
SRCS+=		PrintSCC.cpp
SRCS+=		opt.cpp

LIBADD+=	z

.include "../llvm.prog.mk"
