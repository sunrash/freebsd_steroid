# Makefile for syscall tables
#
# $FreeBSD: releng/12.0/sys/compat/freebsd32/Makefile 328560 2018-01-29 19:14:15Z bdrewery $

# Don't use an OBJDIR
.OBJDIR: ${.CURDIR}

all:
	@echo "make sysent only"

sysent:  freebsd32_sysent.c freebsd32_syscall.h freebsd32_proto.h freebsd32_systrace_args.c

freebsd32_sysent.c freebsd32_syscalls.c freebsd32_syscall.h freebsd32_proto.h freebsd32_systrace_args.c : \
	    ../../kern/makesyscalls.sh syscalls.master syscalls.conf capabilities.conf
	sh ../../kern/makesyscalls.sh syscalls.master syscalls.conf

clean:
	rm -f freebsd32_sysent.c freebsd32_syscalls.c freebsd32_syscall.h freebsd32_proto.h
	rm -f freebsd32_systrace_args.c 
