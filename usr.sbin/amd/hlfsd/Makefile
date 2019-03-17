# ex:ts=8
#
# Makefile for amd
# 	This file is under a "BSD" copyright (c) by David O'Brien 1998
#
# $FreeBSD: releng/12.0/usr.sbin/amd/hlfsd/Makefile 305787 2016-09-14 01:47:01Z cy $

.PATH:	${SRCTOP}/contrib/amd/hlfsd

PROG=	hlfsd
MAN=	hlfsd.8
SRCS=	hlfsd.c homedir.c nfs_prot_svc.c stubs.c

CFLAGS+= -I${SRCTOP}/contrib/amd/hlfsd

LIBADD=	amu

.include <bsd.prog.mk>
