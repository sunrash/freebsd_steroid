# $FreeBSD: releng/12.0/lib/libcasper/Makefile.inc 325062 2017-10-28 19:23:57Z oshogbo $

.include <src.opts.mk>

.if ${MK_CASPER} != "no"
CFLAGS+=-DWITH_CASPER
.endif

.include "../Makefile.inc"
