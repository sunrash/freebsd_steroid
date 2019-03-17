# $FreeBSD: releng/12.0/sbin/ggate/Makefile 265420 2014-05-06 04:22:01Z imp $

.include <src.opts.mk>

SUBDIR=	${_ggatec} \
	${_ggated} \
	ggatel

.if ${MK_LIBTHR} != "no"
_ggatec=	ggatec
_ggated=	ggated
.endif

.include <bsd.subdir.mk>
