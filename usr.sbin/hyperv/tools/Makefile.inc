# $FreeBSD: releng/12.0/usr.sbin/hyperv/tools/Makefile.inc 308743 2016-11-17 03:02:35Z sephe $

CFLAGS.gcc+= -Wno-uninitialized
.include "../../Makefile.inc"
