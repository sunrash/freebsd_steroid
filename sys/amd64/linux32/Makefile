# Makefile for syscall tables
#
# $FreeBSD: releng/12.0/sys/amd64/linux32/Makefile 328560 2018-01-29 19:14:15Z bdrewery $

# Don't use an OBJDIR
.OBJDIR: ${.CURDIR}

all:
	@echo "make sysent only"

sysent:  linux32_sysent.c linux32_syscall.h linux32_proto.h linux32_syscalls.c linux32_systrace_args.c

linux32_sysent.c linux32_syscall.h linux32_proto.h linux32_syscalls.c linux32_systrace_args.c: ../../kern/makesyscalls.sh \
		syscalls.master syscalls.conf
	sh ../../kern/makesyscalls.sh syscalls.master syscalls.conf
