# $FreeBSD: releng/12.0/share/i18n/csmapper/Makefile.inc 314652 2017-03-04 11:26:40Z ngie $

.include <bsd.own.mk>

CSMAPPERDIR?= /usr/share/i18n/csmapper
.if ${MK_STAGING} == "yes"
MKCSMAPPER= ${STAGE_HOST_OBJTOP}/usr/bin/mkcsmapper_static
.endif
MKCSMAPPER?= ${.OBJDIR:H:H:H}/usr.bin/mkcsmapper_static/mkcsmapper_static
