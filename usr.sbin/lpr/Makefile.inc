# $FreeBSD: releng/12.0/usr.sbin/lpr/Makefile.inc 275054 2014-11-25 16:57:27Z bapt $

.include <src.opts.mk>

.if ${MK_INET6_SUPPORT} != "no"
CFLAGS+= -DINET6
.endif

.include "../Makefile.inc"
