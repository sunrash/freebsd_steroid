# $FreeBSD: releng/12.0/lib/libcasper/services/cap_random/Makefile 329452 2018-02-17 12:22:29Z oshogbo $

SHLIBDIR?=	/lib/casper

.include <src.opts.mk>

PACKAGE=libcasper

SHLIB_MAJOR=	1
INCSDIR?=	${INCLUDEDIR}/casper

.if ${MK_CASPER} != "no"
SHLIB=	cap_random

SRCS=	cap_random.c
.endif

INCS=	cap_random.h

LIBADD=	nv

CFLAGS+=-I${.CURDIR}

MAN+=	cap_random.3

MLINKS+=cap_random.3 libcap_random.3
MLINKS+=cap_random.3 cap_random_buf.3

.include <bsd.lib.mk>
