#	@(#)Makefile	8.8 (Berkeley) 6/21/2000
#
# $TSHeader: src/sbin/growfs/Makefile,v 1.4 2000/12/05 19:45:24 tomsoft Exp $
# $FreeBSD: releng/12.0/sbin/growfs/Makefile 324499 2017-10-10 16:17:03Z mckusick $
#

.include <src.opts.mk>

.PATH:	${.CURDIR:H}/mount

PACKAGE=runtime
PROG=   growfs
SRCS=   growfs.c getmntopts.c
MAN=	growfs.8
CFLAGS+=-I${.CURDIR:H}/mount

.if defined(GFSDBG)
SRCS+=	debug.c
CFLAGS+= -DFS_DEBUG
NO_WCAST_ALIGN= yes
.endif

LIBADD=	ufs util

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

.include <bsd.prog.mk>
