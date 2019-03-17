# $FreeBSD: releng/12.0/lib/clang/Makefile.inc 322824 2017-08-23 23:30:25Z jhb $

.include <bsd.compiler.mk>

.if ${COMPILER_TYPE} == "clang"
DEBUG_FILES_CFLAGS= -gline-tables-only
.else
DEBUG_FILES_CFLAGS= -g1
.endif
