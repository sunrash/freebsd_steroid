# $FreeBSD: releng/12.0/usr.sbin/periodic/etc/monthly/Makefile 337648 2018-08-11 17:11:08Z brd $

.include <src.opts.mk>

CONFGROUPS=	CONFS

CONFS=	450.status-security \
	999.local

# NB: keep these sorted by MK_* knobs

.if ${MK_UTMPX} != "no"
CONFGROUPS+=	ACCT
ACCT+=		200.accounting
ACCTDIR=	/etc/periodic/monthly
ACCTMODE=	${BINMODE}
ACCTPACKAGE=	acct
.endif

.include <bsd.prog.mk>
