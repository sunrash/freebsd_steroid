# $FreeBSD: releng/12.0/tools/tools/net80211/wlanwatch/Makefile 265420 2014-05-06 04:22:01Z imp $

PROG=	wlanwatch
BINDIR=	/usr/local/bin
MAN=

.include <src.opts.mk>

.if ${MK_INET6_SUPPORT} != "no"
CFLAGS+= -DINET6
.endif

.include <bsd.prog.mk>
