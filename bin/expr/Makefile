# $FreeBSD: releng/12.0/bin/expr/Makefile 322515 2017-08-14 19:21:37Z ngie $

.include <src.opts.mk>

PACKAGE=runtime
PROG=	expr
SRCS=	expr.y
YFLAGS=

# expr relies on signed integer wrapping
CFLAGS+= -fwrapv

NO_WMISSING_VARIABLE_DECLARATIONS=

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>
