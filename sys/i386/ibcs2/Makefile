# Makefile for syscall tables
#
# $FreeBSD: releng/12.0/sys/i386/ibcs2/Makefile 328560 2018-01-29 19:14:15Z bdrewery $

# Don't use an OBJDIR
.OBJDIR: ${.CURDIR}

all:
	@echo "make sysent, isc_sysent or xenix_sysent only"

sysent:  ibcs2_sysent.c ibcs2_syscall.h ibcs2_proto.h

ibcs2_sysent.c ibcs2_syscall.h ibcs2_proto.h: ../../kern/makesyscalls.sh \
		syscalls.master syscalls.conf
	sh ../../kern/makesyscalls.sh syscalls.master syscalls.conf

isc_sysent:  ibcs2_isc_sysent.c ibcs2_isc_syscall.h

ibcs2_isc_sysent.c ibcs2_isc_syscall.h : ../../kern/makesyscalls.sh \
		syscalls.isc syscalls.isc.conf
	sh ../../kern/makesyscalls.sh syscalls.isc syscalls.isc.conf

xenix_sysent:  ibcs2_xenix_sysent.c ibcs2_xenix_syscall.h ibcs2_xenix.h

ibcs2_xenix_sysent.c ibcs2_xenix_syscall.h ibcs2_xenix.h: \
		../../kern/makesyscalls.sh syscalls.xenix syscalls.xenix.conf
	sh ../../kern/makesyscalls.sh syscalls.xenix syscalls.xenix.conf
