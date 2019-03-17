# $FreeBSD: releng/12.0/lib/geom/Makefile.inc 335645 2018-06-25 19:55:15Z brooks $

.include <src.opts.mk>

SHLIBDIR=${GEOM_CLASS_DIR}
SHLIB_NAME?=geom_${GEOM_CLASS}.so
MAN=	g${GEOM_CLASS}.8
SRCS+=	geom_${GEOM_CLASS}.c subr.c
CFLAGS+=-I${SRCTOP}/sbin/geom

.PATH: ${SRCTOP}/sbin/geom/misc

NO_WMISSING_VARIABLE_DECLARATIONS=

.include "Makefile.classes"
.include "../Makefile.inc"
