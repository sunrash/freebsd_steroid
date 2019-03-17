# $FreeBSD: releng/12.0/share/i18n/esdb/Makefile.inc 314652 2017-03-04 11:26:40Z ngie $

.include <bsd.own.mk>

.PATH: ${.CURDIR}

ESDBDIR?= /usr/share/i18n/esdb
.if ${MK_STAGING} == "yes"
MKESDB= ${STAGE_HOST_OBJTOP}/usr/bin/mkesdb_static
.endif
MKESDB?= ${.OBJDIR:H:H:H}/usr.bin/mkesdb_static/mkesdb_static
