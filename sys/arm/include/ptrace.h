/*	$NetBSD: ptrace.h,v 1.2 2001/02/23 21:23:52 reinoud Exp $	*/
/* $FreeBSD: releng/12.0/sys/arm/include/ptrace.h 323582 2017-09-14 15:03:43Z jhb $ */

#ifndef _MACHINE_PTRACE_H_
#define _MACHINE_PTRACE_H_

#define	__HAVE_PTRACE_MACHDEP

/*
 * Must match mcontext_vfp_t.  Note that mcontext_vfp_t does not
 * include explicit padding.
 */
struct vfpreg {
	__uint64_t	vfp_reg[32];
	__uint32_t	vfp_scr;
	__uint32_t	vfp_pad0;
};

#define	PT_GETVFPREGS	(PT_FIRSTMACH + 0)
#define	PT_SETVFPREGS	(PT_FIRSTMACH + 1)

#endif /* !_MACHINE_PTRACE_H */

