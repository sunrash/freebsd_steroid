#	$NetBSD: Makefile.inc,v 1.7 2005/09/17 11:49:39 tsutsui Exp $
# $FreeBSD: releng/12.0/lib/libc/mips/Makefile.inc 315424 2017-03-16 21:05:21Z brooks $

SRCS+= machdep_ldisd.c
SYM_MAPS+= ${LIBC_SRCTOP}/mips/Symbol.map
