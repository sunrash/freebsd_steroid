#	@(#)Makefile	8.2 (Berkeley) 3/21/94
# $FreeBSD: releng/12.0/sys/kern/Makefile 328560 2018-01-29 19:14:15Z bdrewery $
#
# Makefile for init_sysent

# Don't use an OBJDIR
.OBJDIR: ${.CURDIR}

all:
	@echo "make sysent only"

sysent: init_sysent.c syscalls.c ../sys/syscall.h ../sys/syscall.mk \
../sys/sysproto.h

init_sysent.c syscalls.c systrace_args.c ../sys/syscall.h \
../sys/syscall.mk ../sys/sysproto.h: makesyscalls.sh syscalls.master \
capabilities.conf
	sh makesyscalls.sh syscalls.master
