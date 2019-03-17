# $FreeBSD: releng/12.0/gnu/usr.bin/Makefile 319664 2017-06-07 23:00:34Z bapt $

.include <src.opts.mk>


.if ${MK_CXX} != "no"
SUBDIR.${MK_GCC}+=	gperf
.endif

SUBDIR.${MK_BINUTILS}+=	binutils
SUBDIR.${MK_DIALOG}+=	dialog
SUBDIR.${MK_GCC}+=	cc
SUBDIR.${MK_GNU_DIFF}+=	diff3
SUBDIR.${MK_GNU_GREP}+=	grep
SUBDIR.${MK_GDB}+=	gdb
SUBDIR_DEPEND_gdb=	binutils
SUBDIR.${MK_GPL_DTC}+=	dtc
SUBDIR.${MK_TESTS}+=	tests

SUBDIR_PARALLEL=

.include <bsd.subdir.mk>
