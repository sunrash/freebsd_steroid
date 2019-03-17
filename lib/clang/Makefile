# $FreeBSD: releng/12.0/lib/clang/Makefile 309124 2016-11-24 22:54:55Z dim $

.include <src.opts.mk>

# These have to be built in order.
SUBDIR=		libllvm
SUBDIR+=	libclang
.if ${MK_LLDB} != "no"
SUBDIR+=	liblldb
.endif
SUBDIR+=	headers

.include <bsd.subdir.mk>
