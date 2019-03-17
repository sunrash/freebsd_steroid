# $FreeBSD: releng/12.0/sys/compat/cloudabi64/Makefile 328560 2018-01-29 19:14:15Z bdrewery $

# Don't use an OBJDIR
.OBJDIR: ${.CURDIR}

all:
	@echo "make sysent only"

sysent: cloudabi64_sysent.c cloudabi64_syscall.h cloudabi64_proto.h \
    cloudabi64_syscalls.c cloudabi64_systrace_args.c

cloudabi64_sysent.c cloudabi64_syscall.h cloudabi64_proto.h \
    cloudabi64_syscalls.c cloudabi64_systrace_args.c: \
    ../../kern/makesyscalls.sh ../../contrib/cloudabi/syscalls64.master \
    syscalls.conf
	sh ../../kern/makesyscalls.sh ../../contrib/cloudabi/syscalls64.master \
	    syscalls.conf
