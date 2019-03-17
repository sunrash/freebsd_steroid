# $FreeBSD: releng/12.0/gnu/usr.bin/gdb/Makefile 328925 2018-02-06 11:54:20Z bapt $

.include <src.opts.mk>

SUBDIR=	libgdb gdb kgdb

.if ${MK_GDB_LIBEXEC} == "no"
.if exists(${.CURDIR}/gdbserver/reg-${MACHINE_CPUARCH}.c)
SUBDIR+=gdbserver
.endif
.endif

.include <bsd.subdir.mk>
