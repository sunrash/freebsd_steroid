# $FreeBSD: releng/12.0/usr.bin/clang/bugpoint/Makefile 309124 2016-11-24 22:54:55Z dim $

PROG_CXX=	bugpoint

SRCDIR=		tools/bugpoint
SRCS+=		BugDriver.cpp
SRCS+=		CrashDebugger.cpp
SRCS+=		ExecutionDriver.cpp
SRCS+=		ExtractFunction.cpp
SRCS+=		FindBugs.cpp
SRCS+=		Miscompilation.cpp
SRCS+=		OptimizerDriver.cpp
SRCS+=		ToolRunner.cpp
SRCS+=		bugpoint.cpp

LIBADD+=	z

.include "../llvm.prog.mk"
