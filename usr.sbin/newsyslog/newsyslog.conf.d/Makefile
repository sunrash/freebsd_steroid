# $FreeBSD: releng/12.0/usr.sbin/newsyslog/newsyslog.conf.d/Makefile 337686 2018-08-12 13:24:53Z brd $

.include <src.opts.mk>

CONFSDIR=	/etc/newsyslog.conf.d

CONFS=

.if ${MK_AMD} != "no"
CONFS+=		amd.conf
.endif

.if ${MK_FTP} != "no"
CONFS+=		ftp.conf
.endif

.if ${MK_LPR} != "no"
CONFS+=		lpr.conf
.endif

.if ${MK_OFED} != "no"
CONFS+=		opensm.conf
.endif

.if ${MK_PF} != "no"
CONFS+=		pf.conf
.endif

.if ${MK_PPP} != "no"
CONFS+=		ppp.conf
.endif

.if ${MK_SENDMAIL} != "no"
CONFS+=		sendmail.conf
.endif

.include <bsd.prog.mk>
