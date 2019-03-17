# $FreeBSD: releng/12.0/usr.sbin/hyperv/Makefile.inc 286992 2015-08-21 14:15:54Z imp $

CFLAGS.gcc+= -Wno-uninitialized
.include "../Makefile.inc"
