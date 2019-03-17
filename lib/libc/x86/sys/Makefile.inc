# $FreeBSD: releng/12.0/lib/libc/x86/sys/Makefile.inc 312422 2017-01-19 18:07:24Z ngie $

.PATH:	${LIBC_SRCTOP}/x86/sys

SRCS+= \
	__vdso_gettc.c

.if ${MACHINE_CPUARCH} == "amd64" && ${MK_HYPERV} != "no"
CFLAGS+=	-DWANT_HYPERV
.endif
